#!/usr/bin/python3
import os
import pdb
import platform
import re
import subprocess
import traceback

from source import log
##############################
# Target - by connection type
class Target():
    def __init__(self):
        pass
    
    def dump(self):
        """
        Read interesting files, run interesting commands.
        """
        if not self.os:
            log.err('Cannot dump unknown OS.')
            return None

        result = {}
        # read files
        for key, filename in self.os.files.items():
            log.debug('Reading %s...' % filename)
            result[key] = self.read(filename)
        # run commands
        for key, command in self.os.commands.items():
            log.debug('Trying to run \'%s\'...' % command)
            result[key] = self.execute(command)
        return result


    @staticmethod
    def create_target(path):
        # TODO parse path to determine type
        if path.startswith('/'):
            return Local(subfolder=(None if len(path) == 1 else path))
        elif path.startswith('ssh://'):
            r = re.match(r'ssh:\/\/(\w+)@([\w\-.]+):?([\w\/]+)?$', path)
            if not r:
                log.err('Invalid SSH connection string.')
                return None
            username, host, subfolder = r.groups()
            port = 22 # TODO some support for different
            return SSH(host, port, username, subfolder)
        else:
            log.err('Unsupported target.')
            return None

class Local(Target):
    def __init__(self, subfolder=None):
        super().__init__()
        self.subfolder = subfolder
        self.os = self.determine_os()

    def determine_os(self):
        try:
            with open(os.path.join(self.subfolder or '/', 'etc/passwd'), 'r') as f:
                pass
            log.info('Determined Linux-based OS.')
            return Linux()
        except:
            traceback.print_exc()
            log.err('Could not determine OS.')
        return None
    
    def read(self, filename):
        try:
            with open(os.path.join(self.subfolder or '/', filename.lstrip('/')), 'rb') as f:
                return f.read()
        except:
            return None
    
    def execute(self, command):
        if self.subfolder:
            return None
        p = subprocess.Popen(command,
                             shell=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()
        return out
        

class SSH(Target):
    def __init__(self, host, port, username, subfolder=None):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.subfolder = subfolder

        # connect to server
        import paramiko
        password = None
        while True:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                self.client.connect(self.host, port=self.port, username=self.username, password=password, timeout=5)
                break
            except paramiko.ssh_exception.SSHException as e:
                if not password:
                    import getpass
                    password = getpass.getpass('Password: ')
                    continue
                log.err('No authentication methods available.')
                return
            except paramiko.ssh_exception.AuthenticationException:
                log.err('Authentication failed.')
                return
            except paramiko.ssh_exception.NoValidConnectionsError:
                log.err('Cannot connect to the host over SSH.')
                return
            except:
                traceback.print_exc()
                return
        log.info('Connected to %s.' % self.host)
        self.os = self.determine_os()

    def determine_os(self):
        sftp = self.client.open_sftp()
        try:
            f = sftp.open(os.path.join(self.subfolder or '/', 'etc/passwd'), 'r')
            log.info('Determined Linux-based OS.')
            return Linux()
        except:
            traceback.print_exc()
            log.err('Could not determine OS.')
        finally:
            sftp.close()
        return None
    
    def read(self, filename):
        sftp = self.client.open_sftp()
        try:
            f = sftp.open(os.path.join(self.subfolder or '/', filename.lstrip('/')), 'rb')
            return f.read()
        except:
            traceback.print_exc()
            return None
    
    def execute(self, command):
        if self.subfolder:
            return None
        stdin, stdout, stderr = self.client.exec_command(command)
        return stdout.read()

##############################
# Target - by OS
class OS():
    def __init__(self):
        pass

class Linux(OS):
    def __init__(self):
        super().__init__()
        self.files = {
            'passwd': '/etc/passwd',
            'shadow': '/etc/shadow',
            'os_release': '/etc/os-release',

        }
        self.commands = {
            'rpm': 'rpm -qa',
            'dpkg': 'dpkg -l',
            'ss': 'ss -tupln',
            'iptables': 'iptables -S',
            'ip6tables': 'ip6tables -S',
        }

class Windows(OS):
    def __init__(self):
        super().__init__()
        self.files = {

        }
        self.commands = {

        } 
