#!/usr/bin/env python
from UserDict import UserDict
import multiprocessing

import sys, os, ConfigParser, re, socket, subprocess, threading, optparse, logging
import datetime
import traceback
import pexpect

LOGGING_LEVELS = {
    'crit':     logging.CRITICAL,
    'critical': logging.CRITICAL,
    'err':      logging.ERROR,
    'error':    logging.ERROR,
    'warn':     logging.WARNING,
    'warning':  logging.WARNING,
    'info':     logging.INFO,
    'debug':    logging.DEBUG }

global_pexpect_instance = None # Used by signal handler
global_debug = 0

C_KEYACCEPT		= 0
C_PASSWORD		= 1
C_LOGOUT   		= 2
C_LOGIN			= 3
C_CHATTER  		= 4
C_BADPASS		= 5
C_SUDOSPLAT		= 6
C_OOPS			= 7
C_ROOT			= 8
C_WHITESPACE	= 9
C_HUH			= 10
C_IDS			= 11
C_EOF     		= 12
C_TIMEOUT 		= 13
C_DENIED 		= 14

global_matches = [
				C_KEYACCEPT		,
				C_PASSWORD		,
				C_LOGOUT		,
				C_LOGIN			,
				C_CHATTER  		,
				C_BADPASS		,
				C_SUDOSPLAT		,
				C_OOPS			,
				C_ROOT			,
				C_WHITESPACE	,
				C_HUH			,
				C_IDS			,
				C_EOF     		,
				C_TIMEOUT 		,
				C_DENIED 		,
			]
ssh_newkey = 'Are you sure you want to continue connecting'
global_matches[C_KEYACCEPT] 	= ssh_newkey
global_matches[C_PASSWORD] 	    = '^.*?([Pp]assword(:| for)|(Sorry, try again.)).*?$'
global_matches[C_LOGOUT] 		= '^.*?(exit|logout)\r?\n?'
#global_matches[C_LOGIN] 		= '^.*?%s@%s.*?(\n|$)'%(global_user,global_host)
global_matches[C_CHATTER] 		= '^(Pseudo-terminal.*|Last login:|sudo su -|whoami|\$).*?$'
global_matches[C_BADPASS] 		= '^sudo: .*?incorrect password attempts.*?$'
global_matches[C_SUDOSPLAT] 	= '^sudo: .*?(\n|$)'
global_matches[C_OOPS] 		    = '^.*?command not found.*?$'
global_matches[C_DENIED] 		= '^.*?Permission denied.*?$'
#global_matches[C_ROOT] 		= '^.*?root@%s.*?(\n|$)'%(global_host)
global_matches[C_WHITESPACE] 	= '^[\r\n\t ]*$'
global_matches[C_HUH] 			= '^.+$'
global_matches[C_IDS]			= "^Connecting with this configuration will cause IDS trigger!"
global_matches[C_EOF] 			= pexpect.EOF
global_matches[C_TIMEOUT] 		= pexpect.TIMEOUT


# ======================================================================================================================
class Command(object):
    def __init__(self, cmd, shell=False):
        self.cmd = cmd
        self.process = None
        self.shell = shell

    def process(self):
        return self.process

    def run(self):
        def target():
            self.process = subprocess.Popen(self.cmd, shell=self.shell)
            self.process.communicate()

        self.thread = threading.Thread(target=target)
        self.thread.start()

    def wait(self,timeout):
        self.thread.join(timeout)
        if self.thread.is_alive():
            self.process.terminate()
            self.thread.join()
        return self.process.returncode

# ======================================================================================================================
# exception classes
class ConfigError(Exception):
    """Config exceptions."""

class ASCError(Exception):
    """ASC exceptions."""


class advanced_ssh_config( ):

    def matchLine(self,line,key):
        global global_matches
        global_matches[C_LOGIN] 	= '^.*?%s@.*?(\n|$)'%(self.username) #,self.args['h'])
        global_matches[C_ROOT] 		= '^.*?root@%s.*?(\n|$)'%(self.hostname)

        m = re.compile(global_matches[key])
        return m.match(line)

    def waitForLine(self,child,to=10):
        i = child.expect(['^(.*?\n|$|[^\n]+$)?', pexpect.EOF, pexpect.TIMEOUT], timeout=to) # \r?\n
        if i == 0:
            return re.sub('\r+', '', child.after)
        elif i == 1:
            return ''
        elif i == 2:
            raise Exception("Timeout waiting for response")
        else:
            raise Exception("Unexpected match waiting on a line from the spawned process")

    def doSSH_command(self):

        """This runs a ssh command on the remote hosts.  """
        log = logging.getLogger('')

        host,port,user,idkey,to = self.args['ip'],self.args['p'],self.args['l'],self.args['i'],self.connect_timeout
        if self.username:
            user = self.username
        self.username = user
        if self.port:
            port = self.port
        self.port = port
        self.hostname = self.args['h']
        command='/usr/bin/ssh -o ConnectTimeout=%s -i %s -l %s -p %s %s'%(to,idkey,user,port,host)
        log.debug("Command %s timeout=%d"%(command,to))

        child = pexpect.spawn(command,timeout=to)
        child.logfile_read = self.fout
        self.pexpect_instance = child
        oto=to
        root=0
        tries=0
        prompt = None
        lastline = None

        nested = 1
        while nested > 0:
            #i = child.expect(global_matches,timeout=to)
            line = self.waitForLine(child, to)
            if (lastline == line):
                pass
            else:
                lastline = line
                log.debug("Looking ... nesting:%d ... '%s' '%s'" % (nested, line, lastline))

            if self.matchLine(line,C_KEYACCEPT): # SSH does not have the public key. Just accept it.
                child.sendline ('yes')
            elif self.matchLine(line,C_PASSWORD): # Password
                if tries > 2:
                    raise Exception("Bad password ... tried 3 times")
                else:
                    log.debug('password')
                    child.setecho(False)
                    child.sendline(self.password)
                    child.setecho(True)
                    tries += 1
            elif self.matchLine(line,C_LOGIN): # Success!
                log.debug("Success!" )
                rprompt = child.after
                log.debug("Prompt: '%s'"% rprompt)
                nested += 1
                if 0 == root:
                    root = 1
                    sys.stdout.write (rprompt)
                    child.setecho(False)
                    child.interact(escape_character=chr(24))
                    sys.stdout.flush()
                nested = 0

            elif self.matchLine(line,C_DENIED): # Nope!
                log.debug("%s%s"%(child.before, child.after) )
                self.fout.flush()
                nested = 0

            elif self.matchLine(line,C_CHATTER): # We expect these ...
                log.debug("Ignoring chatter ...before:'%s' '%s'"%(child.before, child.after) )
                self.fout.flush()
            elif self.matchLine(line,C_LOGOUT):
                log.debug("Log out ... ")
                nested = 0

            elif self.matchLine(line,C_WHITESPACE):
                #log.debug("Nothing ... ")
                if child.after != pexpect.EOF:
                    s = re.sub('%s' % re.escape(self.password), '', child.after)
                    sys.stdout.write( s )
                    child.after = ''

            elif self.matchLine(line,C_IDS):
                self.fout.flush()
                s = re.sub('%s' % re.escape(self.password), '', child.after)
                print s
                nested = 0

            elif self.matchLine(line,C_HUH): # Something unexpected ...
                s = re.sub('%s' % re.escape(self.password), '', child.after)
                sys.stdout.write( s )
                child.after = ''

            elif self.matchLine(line,C_BADPASS):
                msg = "Bad password ... before: '%s' after: '%s'"%(child.before, child.after)
                log.debug(msg)
                self.fout.flush()
                raise Exception(msg)

            else: # if i < 0 or i > 7: # Catch all
                msg = "Unhandled output. before: '%s' after: '%s'"%(child.before, child.after)
                log.error( msg )
                self.fout.flush()
                raise Exception(msg)


        log.debug("'%s' complete %d"%(command,nested))
        self.fout.write( '' )
        self.fout.flush()
        return child

    def __getattr__(self, method_name):
        """
            This is called every time a class method or property
            is checked and/or called.

            In here we'll return a new function to handle what we
            want to do.
        """
        if re.search( 'options', method_name):
            raise AttributeError, method_name

        if 'configfiles' == method_name:
            self.__dict__[method_name] = self.options['configfile']
            return self.options['configfile']

        if self.options.has_key(method_name):
            self.__dict__[method_name] = self.options[method_name]
            return self.options[method_name]
        else:
            # If the method isn't in our dictionary, act normal.
            raise AttributeError, method_name


    def __init__( self, options = None ):
        self.defaults = {
            'hostname':         None,
            'port':             '22',
            'configfile':       [ '/etc/ssh/config.advanced', os.path.expanduser( "~/.ssh/config.advanced" ) ],
            'verbose':          False,
            'update_sshconfig': False,
            'connect_timeout':  5,
            'proxy_mode':       False,
            'username':         '',
            'log_file':         '/tmp/advanced-ssh-config.py.log',
            'ssh_config':       os.path.expanduser( '~/.ssh/config' ),
        }
        if not options:
            options = self.defaults
        else:
            for key in self.defaults:
                if not options.has_key(key) or not options[key]:
                    options[key] = self.defaults[key]
        self.options = options
        self.log = logging.getLogger( '' )

        self.parser = ConfigParser.ConfigParser( )
        self.parser.SECTCRE = re.compile(
            r'\['                                 # [
            r'(?P<header>.+)'                     # very permissive!
            r'\]'                                 # ]
        )

        errors = 0
        self.parser.read( self.configfiles )
        includes = self.conf_get( 'includes', 'default', '' ).strip( )
        for include in includes.split( ):
            incpath = os.path.expanduser( include )
            if not incpath in self.configfiles and os.path.exists( incpath ):
                self.parser.read( incpath )
            else:
                self.log.error("'%s' include not found" % incpath )
                errors += 1

        if 0 == errors:
            self.debug( )
            self.debug( "configfiles : %s" % self.configfiles )
            self.debug( "================" )
        else:
            raise ConfigError('Errors found in config')

        for key in self.options:
            #noinspection PyStatementEffect
            if self.options[key] == None:
                if re.search( '^(username|password|command|hostname)', key ):
                    self.options[key] = ''
                else:
                    raise Exception("'%s' cannot be 'None'" % key)

        if self.update_sshconfig:
            self._update_sshconfig( )


    def debug( self, str = None, force = False ):
        if force:
            self.log.info(str and str or '')
        else:
            self.log.debug(str and str or '')

    def host_get( self, host ):
        for section in self.parser.sections( ):
            if re.match( section, host ):
                return section
        return None

    def conf_get( self, key, host, default = None, vardct = None ):
        for section in self.parser.sections( ):
            if re.match( section, host ):
                if self.parser.has_option( section, key ):
                    return self.parser.get( section, key, False, vardct )
        if self.parser.has_option( 'default', key ):
            return self.parser.get( 'default', key )
        return default

    def resolve_host( self ):
        start = datetime.datetime.now( )
        try:
            #self.args[ 'h' ] = 'impossible'
            self.debug( "Resolving '%s' ..." % self.args[ 'h' ] )
            self.args['ip'] = socket.gethostbyname( self.args[ 'h' ] )
            return self.args['ip']
        except Exception as e:
            now = datetime.datetime.now( )
            self.log.error( "ERROR: Cannot resolve host '%s' ( %s ) after %ds" % (self.args[ 'h' ], e.__str__( ), (now - start).seconds) )
            raise Exception( "Cannot resolve host '%s'" % self.args[ 'h' ] )

    def connect( self ):
        # Handle special settings
        mkdir_path = os.path.dirname(
            os.path.join( os.path.dirname( os.path.expanduser( self.conf_get( 'controlpath', 'default', '/tmp' ) ) ),
                          self.hostname ) )
        try:
            os.makedirs( mkdir_path )
        except:
            pass

        section = self.host_get( self.hostname )
        sectdct = {}
        for i,s in enumerate(self.parser.items(section,True)):
            sectdct[s[0]] = s[1]

        if not (section and sectdct):
            raise ConfigError("'%s' section not found!" % self.hostname )
        self.log.info( "section '%s' " % section )

        # Parse special routing
        path = self.hostname.split( '/' )

        self.args = { }
        opt_map = { 'p': 'Port',
                    'l': 'User',
                    'h': 'Hostname',
                    'i': 'IdentityFile' }

        updated = False
        for key in opt_map:
            default = False
            k = opt_map[key].lower()
            if self.options.has_key(k):
                default = self.options[k]
            cfval = self.conf_get( opt_map[ key ], path[ 0 ], default, { 'hostname': self.hostname, 'port': self.port } )
            value = self._interpolate(cfval)
            if cfval != value:
                updated = True
                self.parser.set(section,opt_map[key],value)
                self.args[ key ] = value

            self.debug( "get (-%-1s) %-12s : %s" % (key, opt_map[ key ], value) )
            if value:
                self.args[ key ] = value

        # If we interpolated any keys
        if updated:
            self._update_sshconfig( )
            self.log.debug("Config updated. Need to restart SSH!?")

        if not 'h' in self.args:
            self.args[ 'h' ] = path[ 0 ]
        if 'i' in self.args:
            self.args[ 'i' ] = os.path.expanduser(self.args[ 'i' ])
        self.debug( 'args: %s' % self.args )
        self.debug( )

        self.debug( "hostname    : %s" % self.hostname )
        self.debug( "port        : %s" % self.port )
        self.debug( "path        : %s" % path )
        self.debug( "path[0]     : %s" % path[ 0 ] )
        self.debug( "path[1:]    : %s" % path[ 1: ] )
        self.debug( "args        : %s" % self.args )

        self.debug( )
        gateways = self.conf_get( 'Gateways', path[ -1 ], 'direct' ).strip( ).split( ' ' )
        reallocalcommand = self.conf_get( 'RealLocalCommand', path[ -1 ], '' ).strip( ).split( ' ' )
        self.debug( "reallocalcommand: %s" % reallocalcommand )
        for gateway in gateways:
            right_path = path[ 1: ]
            cmd = [ 'ssh' ]

            self.debug( "host         : %s" % self.args['h'] )
            self.resolve_host( )

            if self.args.has_key('ip'):
                self.debug( "host address : %s" % self.args['ip'] )
            else:
                raise Exception("Unable to resolve '%s" % self.args['h'])

            host,port,user,idkey,to = self.args['ip'],self.args['p'],self.args['l'],self.args['i'],self.connect_timeout
            if self.username:
                user = self.username
            if self.port:
                port = self.port
            if self.proxy_mode:
                if gateway != 'direct':
                    right_path += [ gateway ]
            else:
                cmd += [ '-o', 'ConnectTimeout=%s' % to, '-i', idkey, '-l', user, '-p', port ]
                for key in sectdct:
                    if not re.search('^(host|identityfile|gateway|user)', key.lower()):
                        cmd += [ '-o', "%s=%s" %(key, sectdct[key]) ]
                if gateway != 'direct':
                    #gateway_l = gateway.split(':')
                    #gateway_h = gateway_l.pop(0)
                    #gateway_p = '22'
                    #if len(gateway_l) > 0:
                    #    gateway_p = gateway_l.pop(0)
                    #cmd += [ '-o', "ProxyCommand='ssh -q -t nc %s %s'" %(gateway_h,gateway_p) ]
                    right_path += [ self.args['ip'] ]

            if len( right_path ):
                cmd += [ '/'.join( right_path ) ]

            if self.proxy_mode:
                cmd += [ 'nc', self.args['ip'], self.args['p'] ]

            self.debug( "cmd         : %s" % ' '.join(cmd) )
            self.debug( "================================================" )
            self.debug( )

            if self.proxy_mode:
                try:
                    if gateway == 'direct':
                        socket.create_connection((self.args['ip'],self.args['p']),self.connect_timeout)
                    else:
                        gateway_l = gateway.split(':')
                        gateway_h = gateway_l.pop(0)
                        gateway_p = '22'
                        if len(gateway_l) > 0:
                            gateway_p = gateway_l.pop(0)
                        socket.create_connection((gateway_h,gateway_p),self.connect_timeout)
                except Exception as e:
                    raise ASCError("Cannot connect to %s:%s within %3.1s (%s)" % (self.args['ip'],self.args['p'],self.connect_timeout, e.message))

                start = datetime.datetime.now()
                ssh_process = subprocess.Popen( cmd )
                reallocalcommand_process = None
                if len( reallocalcommand[ 0 ] ):
                    reallocalcommand_process = subprocess.Popen( reallocalcommand )
                ssh_ret = ssh_process.wait()
                now = datetime.datetime.now()
                duration = (now-start)
                if ssh_ret != 0:
                    self.log.critical( "Proxy command failed after %fs. (%s)" % (duration.seconds,ssh_ret) )
                if reallocalcommand_process != None:
                    reallocalcommand_process.kill( )
            else:
                self.fout_file=self.defaults["log_file"]
                if self.log_file != None:
                    log_file = self.log_file
                    self.fout_file = "%s.con"%log_file
                mode = 'wb'

                #noinspection PyRedeclaration
                self.fout = file (self.fout_file, mode)
                self.doSSH_command()

    def _update_sshconfig( self, write = True ):
        config = [ ]

        for section in self.parser.sections( ):
            if section != 'default':
                host = section
                host = re.sub( '\.\*', '*', host )
                host = re.sub( '\\\.', '.', host )
                config += [ "Host %s" % host ]
                for key, value in self.parser.items( section, False, { 'Hostname': host } ):
                    if key not in [ 'hostname', 'gateways', 'reallocalcommand', 'remotecommand' ]:
                        if key == 'alias':
                            key = 'hostname'
                        config += [ "  %s %s" % (key, value) ]
                config += [ '' ]

        config += [ 'Host *' ]
        for key, value in self.parser.items( 'default' ):
            if key not in [ 'hostname', 'gateways', 'includes' ]:
                config += [ "  %s %s" % (key, value) ]

        if write:
            file = open( os.path.expanduser( self.ssh_config ), 'w+' )
            file.write( '\n'.join( config ) )
            file.close( )
        else:
            print '\n'.join( config )

    def _interpolate( self, value ):

        matches = value and re.match( '\$(\w+)', value ) or None
        if matches:
            var = matches.group(1)
            val = os.environ.get(var)
            if val:
                self.log.debug("'%s' => '%s'" % (value, val))
                return self._interpolate(re.sub('\$%s' % var,val,value))

        return value

if __name__ == "__main__":
    if hasattr(socket, 'setdefaulttimeout'):
        socket.setdefaulttimeout(5)
    parser = optparse.OptionParser( usage = "%prog [-v] --hostname=hostname --port=port", version = "%prog 1.0" )
    parser.add_option( "-t", "--timeout", dest = "connect_timeout", help = "Connect timeout" )
    parser.add_option( "-H", "--hostname", dest = "hostname", help = "Host" )
    parser.add_option(       "--port", dest = "port" )
    parser.add_option( "-p", "--proxy", dest = "proxy_mode", action = "store_true" )
    parser.add_option( "-v", "--verbose", dest = "verbose", action = "store_true" )
    parser.add_option( '-F', '--config', dest='ssh_config', help='SSH config file name')
    parser.add_option( '-f', '--log-file', dest='log_file', help='Logging file name')
    parser.add_option( "-l", "--log_level", dest = "log_level" )
    parser.add_option( "-u", "--update-sshconfig", dest = "update_sshconfig", action = "store_true" )
    parser.add_option( '-U', '--user', dest="username", help='User name')
    parser.add_option( '-P', '--password', dest="password", help='Password')
    parser.add_option( '-c', '--command', dest="command", help='Command to run with sudo remotely')
    (options, args) = parser.parse_args( )
    # You can access command-line arguments using the args variable.

    log_file = None
    if not options.log_level:
        options.log_level = 'error'
    if options.verbose and options.log_level == 'error':
        options.log_level = 'info'
    logging_level = LOGGING_LEVELS.get( options.log_level, logging.ERROR )
    logging.basicConfig( level      = logging_level,
                         filename   = log_file,
                         format     = '%(asctime)s %(levelname)s: %(message)s',
                         datefmt    = '%Y-%m-%d %H:%M:%S' )
    log = logging.getLogger( '' )
    for key in sorted(os.environ):
        if not re.search( '^(rvm|_rvm|__rvm|fg_|bold|reset|pathmunge)', key):
            log.debug("ENV: %s: %s" % (key, os.environ[key]))

    if options.ssh_config:
        options.ssh_config = os.path.expanduser(options.ssh_config)

    try:
        if not options.hostname:
            if len(args) > 0:
                list = args[0].split(':')
                options.hostname = list.pop(0)
                if len(list) > 0:
                    options.port = list.pop(0)

        ssh = advanced_ssh_config( options.__dict__ )
        if ssh.hostname == '':
            print "Must specify a host!\n"
        else:
            ssh.connect( )
    except ConfigError as e:
        sys.stderr.write(e.message)
    except ASCError as e:
        sys.stderr.write(e.message)
    except Exception as e:
        sys.stderr.write( "ERROR: ")
        traceback.print_exc()
        log.error(e.__str__())
