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
        # run file finders to know which files to read
        for key, command in self.os.file_finders.items():
            log.debug('Trying to locate files for \'%s\'...' % key)
            files = self.execute(command).decode().split()
            for f in files:
                log.debug('  Reading %s...' % f)
                result[key + '_' + re.sub(r'[\\\/:]', '_', f)] = self.read(f)
        # determine ownership and permissions of files/directories
        # TODO
        ###
        return result


    @staticmethod
    def create_target(path):
        # TODO parse path to determine type
        if path.startswith('/'):
            return Local(subfolder=(None if len(path) == 1 else path))
        else:
            # SSH
            r = re.match(r'(\w+)@([\w\-.]+):?([\w\/]+)?$', path)
            if r:
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
        # TODO support hierarchical search (e.g. Linux -> Android)
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
        except FileNotFoundError:
            return None
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
        self.files = {}        # files to copy
        self.commands = {}     # commands to run
        self.file_finders = {} # commands to find files to copy
        # TODO
        # post/multi/gather/docker_creds
        #                   enum_vbox
        #                   env
        #                   filezilla_client_cred
        #                   find_vmx
        #                   firefox_creds
        #                   gpg_creds
        #                   irssi_creds
        #                   jboss_gather
        #                   jenkins_gather
        #                   lastpass_creds
        #                   maven_creds
        #                   pidgin_cred
        #                   remmina_creds
        #                   skype_enum
        #                   ssh_creds
        #                   thunderbird_creds
        #                   tomcat_gather
        #                   wlan_geolocate
        # 


class Linux(OS):
    def __init__(self):
        super().__init__()
        ##########
        # OS info
        self.files['os_release'] = '/etc/os-release'
        self.commands['uname'] = 'uname -a'
        self.commands['env'] = 'env'
        self.commands['dmesg'] = 'dmesg'
        self.commands['selinux'] = 'getenforce'
        self.commands['w'] = 'w'
        self.commands['last'] = 'last'
        self.commands['lastlog'] = 'lastlog'
        ################
        # user accounts
        self.files['passwd'] = '/etc/passwd'
        self.files['shadow'] = '/etc/shadow'
        self.files['authorized_keys_root'] = '/root/.ssh/authorized_keys'
        self.file_finders['authorized_keys'] = 'find /home -name authorized_keys'
        self.files['id_rsa_root'] = '/root/.ssh/id_rsa'
        self.file_finders['id_rsa'] = 'find /home -name id_rsa'
        self.files['id_rsa_pub_root'] = '/root/.ssh/id_rsa.pub'
        self.file_finders['id_rsa_pub'] = 'find /home -name id_rsa.pub'
        self.file_finders['history'] = 'find /home -name .*_history'
        self.file_finders['history_root'] = 'find /root -name .*_history'
        self.file_finders['vim_history'] = 'find /home -name .viminfo'
        self.file_finders['vim_history_root'] = 'find /root -name .viminfo'
        ##########
        # storage
        self.files['fstab'] = '/etc/fstab'
        self.commands['mount'] = 'mount'
        self.commands['fdisk'] = 'fdisk -l'
        self.commands['df'] = 'df -h'
        self.files['ecryptfs_root'] = '/root/.ecryptfs'
        self.file_finders['ecryptfs'] = 'find /home/ -name .ecryptfs'
        ##########
        # CRON
        self.files['crontab'] = '/etc/crontab'
        self.file_finders['cron.d'] = 'find /etc/cron.d/ -type f'
        self.file_finders['cron.minutely'] = 'find /etc/cron.minutely/ -type f'
        self.file_finders['cron.hourly'] = 'find /etc/cron.hourly/ -type f'
        self.file_finders['cron.daily'] = 'find /etc/cron.daily/ -type f'
        self.file_finders['cron.weekly'] = 'find /etc/cron.weekly/ -type f'
        self.file_finders['cron.monthly'] = 'find /etc/cron.monthly/ -type f'
        self.file_finders['cron_spool'] = 'find /var/spool/cron/crontabs/ -type f'
        #####################
        # software, services
        self.commands['systemctl'] = 'systemctl'
        self.commands['rpm'] = 'rpm -qa'
        self.commands['dpkg'] = 'dpkg -l'
        self.commands['equery'] = 'equery list'
        self.commands['pacman'] = 'pacman -Q'
        self.commands['commands'] = 'compgen -back'
        # TODO httpd
        self.files['sshd_config'] = '/etc/ssh/sshd_config'
        self.files['apache2.conf'] = '/etc/apache2/apache2.conf'
        self.file_finders['apache_sites'] = 'find /etc/apache2/sites-enabled/ -type f'
        self.files['apache2_ports.conf'] = '/etc/apache2/ports.conf'
        self.files['nginx.conf'] = '/etc/nginx/nginx.conf'
        self.file_finders['apache_sites'] = 'find /etc/nginx/sites-enabled/ -type f'
        self.files['snort.conf'] = '/etc/snort/snort.conf'
        self.files['mysql_my.cnf'] = '/etc/mysql/my.cnf'
        self.files['security.access.conf'] = '/etc/security.access.conf'
        self.files['shells'] = '/etc/shells'
        self.files['security_sepermit.conf'] = '/etc/security/sepermit.conf'
        self.files['ca_certificates.conf'] = '/etc/ca-certificates.conf'
        self.files['security_access.conf'] = '/etc/security/access.conf'
        self.files['gated.conf'] = '/etc/gated.conf'
        self.files['rpc'] = '/etc/rpc'
        self.files['psad.conf'] = '/etc/psad/psad.conf'
        self.files['mysql_debian.cnf'] = '/etc/mysql/debian.cnf'
        self.files['chkrootkit.conf'] = '/etc/chkrootkit.conf'
        self.files['logrotate.conf'] = '/etc/logrotate.conf'
        self.files['rkhunter.conf'] = '/etc/rkhunter.conf'
        self.files['smb.conf'] = '/etc/samba/smb.conf'
        self.files['ldap.conf'] = '/etc/ldap/ldap.conf'
        self.files['openldap.conf'] = '/etc/openldap/openldap.conf'
        self.files['cups.conf'] = '/etc/cups/cups.conf'
        self.files['lampp_httpd.conf'] = '/etc/opt/lampp/etc/httpd.conf'
        self.files['sysctl.conf'] = '/etc/sysctl.conf'
        self.files['proxychains.conf'] = '/etc/proxychains.conf'
        self.files['cups_snmp.conf'] = '/etc/cups/snmp.conf'
        self.files['sendmail.conf'] = '/etc/mail/sendmail.conf'
        self.files['snmp.conf'] = '/etc/snmp/snmp.conf'
        self.files['phpmyadmin_config-db.php'] = '/etc/phpmyadmin/config-db.php'
        self.file_finders['tor'] = 'locate torrc | grep -v ".gz$"' # grep for HiddenServiceDir
        ##########
        # network
        self.commands['ip_ad'] = 'ip ad'
        self.commands['ip_ro'] = 'ip ro'
        self.files['resolv.conf'] = '/etc/resolv.conf'
        self.files['hosts'] = '/etc/hosts'
        self.commands['ss'] = 'ss -tupln'
        self.commands['connections'] = 'lsof -nPi'
        self.commands['iwconfig'] = 'iwconfig'
        self.commands['iptables'] = 'iptables -S'
        self.commands['iptables_nat'] = 'iptables -S -t nat'
        self.commands['iptables_mangle'] = 'iptables -S -t mangle'
        self.commands['ip6tables'] = 'ip6tables -S'
        self.commands['ip6tables_nat'] = 'ip6tables -S -t nat'
        self.commands['ip6tables_mangle'] = 'ip6tables -S -t mangle'
        self.files['ufw.conf'] = '/etc/ufw/ufw.conf'
        self.files['ufw_sysctl.conf'] = '/etc/ufw/sysctl.conf'
        self.files['hosts.allow'] = '/etc/hosts.allow'
        self.files['hosts.deny'] = '/etc/hosts.deny'
        self.file_finders['NetworkManager'] = 'find /etc/NetworkManager/system-connections/ -type f'
        self.files['chap-secrets'] = '/etc/ppp/chap-secrets'
        #################
        # virtualization
        self.files['dockerenv'] = '/.dockerenv'
        self.files['init_cgroup'] = '/proc/1/cgroup'
        self.commands['env_container'] = 'env | grep -i "^container"'
        self.commands['dmidecode'] = 'dmidecode' # look at Handle 0x1
        self.commands['lsmod'] = 'lsmod'         # grep for vbox, vmw, xen, virtio, hv_
        self.files['scsi'] = '/proc/scsi/scsi'
        self.commands['lspci'] = 'lspci'
        self.commands['lscpu'] = 'lscpu'
        # also check dmesg 
        # also check env for 'container'
        #################
        # miscellaneous
        self.file_finders['aws_config'] = 'find /home -wholename *.aws/config'
        self.file_finders['aws_config_root'] = 'find /root -wholename *.aws/config'
        self.file_finders['aws_credentials'] = 'find /home -wholename *.aws/credentials'
        self.file_finders['aws_credentials_root'] = 'find /root -wholename *.aws/credentials'
        self.file_finders['s3cfg'] = 'find /home -name .s3cfg'
        self.file_finders['s3cfg_root'] = 'find /root -name .s3cfg'
        self.file_finders['mongodb_history'] = 'find /home -name .dbshell'
        self.file_finders['mongodb_history_root'] = 'find /root -name .dbshell'
        self.file_finders['xchat'] = 'find /home/*/.xchat2 -type f'
        self.file_finders['xchat_root'] = 'find /root/.xchat2 -type f'
        self.file_finders['fetchmailrc'] = 'find /home -name .fetchmailrc'
        self.files['fetchmailrc_root'] = '/root/.fetchmailrc'
        self.file_finders['netrc'] = 'find /home -name .netrc'
        self.files['netrc_root'] = '/root/.netrc'
        self.files['rsyncd'] = '/etc/rsyncd.conf'
        self.file_finders['rsyncd'] = 'find /home -name .rsyncd.conf'
        self.files['rsyncd_root'] = '/root/.rsyncd.conf'


        

        # TODO
        # post/linux/busybox/enum_connections    
        # post/linux/busybox/enum_hosts          
        # post/linux/gather/gnome_commander_creds
        # post/linux/gather/gnome_keyring_dump   
        # post/linux/gather/openvpn_credentials  
        #                   netrc_creds
        #                   rsyncd_creds
        # 


class Windows(OS):
    def __init__(self):
        super().__init__()
        # TODO
        # post/windows/gather/ad_to_sqlite                      
        # post/windows/gather/arp_scanner                       
        # post/windows/gather/bitcoin_jacker                    
        # post/windows/gather/bitlocker_fvek                    
        # post/windows/gather/cachedump                         
        # post/windows/gather/checkvm                           
        # post/windows/gather/credentials/avira_password        
        # post/windows/gather/credentials/bulletproof_ftp       
        # post/windows/gather/credentials/coreftp               
        # post/windows/gather/credentials/credential_collector  
        # post/windows/gather/credentials/domain_hashdump       
        # post/windows/gather/credentials/dynazip_log           
        # post/windows/gather/credentials/dyndns                
        # post/windows/gather/credentials/enum_cred_store       
        # post/windows/gather/credentials/enum_laps             
        # post/windows/gather/credentials/enum_picasa_pwds      
        # post/windows/gather/credentials/epo_sql               
        # post/windows/gather/credentials/filezilla_server      
        # post/windows/gather/credentials/flashfxp              
        # post/windows/gather/credentials/ftpnavigator          
        # post/windows/gather/credentials/ftpx                  
        # post/windows/gather/credentials/gpp                   
        # post/windows/gather/credentials/heidisql              
        # post/windows/gather/credentials/idm                   
        # post/windows/gather/credentials/imail                 
        # post/windows/gather/credentials/imvu                  
        # post/windows/gather/credentials/mcafee_vse_hashdump   
        # post/windows/gather/credentials/mdaemon_cred_collector
        # post/windows/gather/credentials/meebo                 
        # post/windows/gather/credentials/mremote                
        # post/windows/gather/credentials/mssql_local_hashdump   
        # post/windows/gather/credentials/nimbuzz                
        # post/windows/gather/credentials/outlook                
        # post/windows/gather/credentials/purevpn_cred_collector 
        # post/windows/gather/credentials/razer_synapse          
        # post/windows/gather/credentials/razorsql               
        # post/windows/gather/credentials/rdc_manager_creds      
        # post/windows/gather/credentials/skype                  
        # post/windows/gather/credentials/smartermail            
        # post/windows/gather/credentials/smartftp               
        # post/windows/gather/credentials/spark_im               
        # post/windows/gather/credentials/sso                    
        # post/windows/gather/credentials/steam                  
        # post/windows/gather/credentials/tortoisesvn            
        # post/windows/gather/credentials/total_commander        
        # post/windows/gather/credentials/trillian               
        # post/windows/gather/credentials/vnc                    
        # post/windows/gather/credentials/windows_autologin      
        # post/windows/gather/credentials/winscp                 
        # post/windows/gather/credentials/wsftp_client           
        # post/windows/gather/dnscache_dump                      
        # post/windows/gather/dumplinks                          
        # post/windows/gather/enum_ad_bitlocker                  
        # post/windows/gather/enum_ad_computers                  
        # post/windows/gather/enum_ad_groups                     
        # post/windows/gather/enum_ad_managedby_groups           
        # post/windows/gather/enum_ad_service_principal_names    
        # post/windows/gather/enum_ad_to_wordlist                
        # post/windows/gather/enum_ad_user_comments              
        # post/windows/gather/enum_ad_users                      
        # post/windows/gather/enum_applications                  
        # post/windows/gather/enum_artifacts                     
        # post/windows/gather/enum_av_excluded                   
        # post/windows/gather/enum_chrome                        
        # post/windows/gather/enum_computers           
        # post/windows/gather/enum_db                  
        # post/windows/gather/enum_devices             
        # post/windows/gather/enum_dirperms            
        # post/windows/gather/enum_domain              
        # post/windows/gather/enum_domain_group_users  
        # post/windows/gather/enum_domain_tokens       
        # post/windows/gather/enum_domain_users        
        # post/windows/gather/enum_domains             
        # post/windows/gather/enum_emet                
        # post/windows/gather/enum_files               
        # post/windows/gather/enum_hostfile            
        # post/windows/gather/enum_ie                  
        # post/windows/gather/enum_logged_on_users     
        # post/windows/gather/enum_ms_product_keys     
        # post/windows/gather/enum_muicache            
        # post/windows/gather/enum_patches             
        # post/windows/gather/enum_powershell_env      
        # post/windows/gather/enum_prefetch            
        # post/windows/gather/enum_proxy               
        # post/windows/gather/enum_putty_saved_sessions
        # post/windows/gather/enum_services            
        # post/windows/gather/enum_shares              
        # post/windows/gather/enum_snmp                
        # post/windows/gather/enum_termserv            
        # post/windows/gather/enum_tokens              
        # post/windows/gather/enum_tomcat              
        # post/windows/gather/enum_trusted_locations   
        # post/windows/gather/enum_unattend            
        # post/windows/gather/file_from_raw_ntfs       
        # post/windows/gather/forensics/browser_history
        # post/windows/gather/forensics/duqu_check     
        # post/windows/gather/forensics/enum_drives    
        # post/windows/gather/forensics/imager         
        # post/windows/gather/forensics/nbd_server     
        # post/windows/gather/forensics/recovery_files 
        # post/windows/gather/hashdump                 
        # post/windows/gather/local_admin_search_enum  
        # post/windows/gather/lsa_secrets              
        # post/windows/gather/make_csv_orgchart        
        # post/windows/gather/memory_grep              
        # post/windows/gather/netlm_downgrade          
        # post/windows/gather/ntds_grabber             
        # post/windows/gather/ntds_location            
        # post/windows/gather/outlook                  
        # post/windows/gather/phish_windows_credentials
        # post/windows/gather/psreadline_history       
        # post/windows/gather/resolve_sid              
        # post/windows/gather/reverse_lookup           
        # post/windows/gather/screen_spy               
        # post/windows/gather/smart_hashdump           
        # post/windows/gather/tcpnetstat               
        # post/windows/gather/usb_history              
        # post/windows/gather/win_privs                
        # post/windows/gather/wmic_command             
        # post/windows/gather/word_unc_injector        
        # post/windows/recon/computer_browser_discovery
        # post/windows/recon/outbound_ports            
        # post/windows/recon/resolve_ip                
        #              wlan/wlan_bss_list
        #                   wlan_current_connection
        #                   wlan_profile



class Android(Linux):
    def __init__(self):
        super().__init__()
        # TODO
        # post/android/gather/sub_info
        #                     wireless_ap


class iOS(OS):
    def __init__(self):
        super().__init__()
        # TODO 
        # post/apple_ios/gather/ios_image_gather
        #                       ios_text_gather 


class Cisco(OS):
    def __init__(self):
        super().__init__()
        # TODO
        # post/cisco/gather/enum_cisco


class Juniper(OS):
    def __init__(self):
        super().__init__()
        # TODO
        # post/juniper/gather/enum_juniper


class OSX(Linux): # TODO inherit from Linux?
    def __init__(self):
        super().__init__()
        # TODO
        # post/osx/gather/apfs_encrypted_volume_passwd
        # post/osx/gather/autologin_password          
        # post/osx/gather/enum_adium                  
        # post/osx/gather/enum_airport                
        # post/osx/gather/enum_chicken_vnc_profile    
        # post/osx/gather/enum_colloquy               
        # post/osx/gather/enum_keychain               
        # post/osx/gather/enum_messages               
        # post/osx/gather/enum_osx                    
        # post/osx/gather/hashdump                    
        # post/osx/gather/password_prompt_spoof       
        # post/osx/gather/safari_lastsession          
        # post/osx/gather/vnc_password_osx            


class Solaris(OS):
    def __init__(self):
        super().__init__()
        # TODO
        # post/solaris/gather/checkvm      
        # post/solaris/gather/enum_packages
        # post/solaris/gather/enum_services
        # post/solaris/gather/hashdump     

