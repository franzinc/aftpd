;; $Id: config.cl,v 1.6 2006/02/22 17:35:21 dancy Exp $

(defparameter *logfile* "/var/log/ftp")
(defparameter *xferlog* "/var/log/xferlog")

(defparameter *ftpport* 21)
(defparameter *ftpdataport* 20)

;; The number of ftp connections is limited to *maxusers*.  If *maxusers*
;; is 'nil' (the default), then there is no limit.
(defparameter *maxusers* nil) 

;; *toomanymsg* specifes the path to a text file to be transmitted
;; along with the usual "Connection limit exceeded" message.
;; If this is 'nil' or the file doesn't exist, no additional message
;; is transmitted.
(defparameter *toomanymsg* "/etc/toomany.msg")

;; Location of file used to keep track of connection count
(defparameter *pidsfile* "/var/run/ftp.pids")

;; The initial connection message.  Some might want to change this for
;; security reasons.
(defparameter *banner* "Welcome to Allegro FTP")

;; Control channel timeout.  default -- 5 minutes
(defparameter *idletimeout* (* 5 60))

;; The maximum number of seconds between writes to the data socket
(defparameter *transfertimeout* 120)

;; Maximum time to wait for PASV or PORT connections to complete.
(defparameter *connecttimeout* 60)

;; How long to wait before responding to an invalid password. 
(defparameter *badpwdelay* 5)

;; How many invalid passwords before we disconnect suddenly.
(defparameter *max-password-attempts* 2)

;; The range of ports used for PASV FTP requests.  You'll either want
;; to change or override these, or update your firewall settings to
;; allow incoming connections to these ports.
(defparameter *pasvrange* '(35000 . 39999))

;; IP address to return in response to PASV command.  This can be left
;; 'nil' for most people.  However, if you have special needs due to
;; network address translation, this can help you.  This parameter
;; should be a list of conses w/ the following layout: 
;;   car: string w/ address of network in either a.b.c.d/x.y.z.w
;;        (address/netmask) format or a.b.c.d/x (CIDR) format.  
;;   cdr: string w/ PASV IP address to use for clients matching that
;;        network.  
;; The IP address reported to the client is chosen from the
;; best match in this list.  Note that this does not affect the IP
;; interface to which the passive connection is bound.  It only
;; controls the address which is reported to the client.  See the
;; README file for additional information and a contrived example.
(defparameter *pasvipaddrs* nil)

;; If you only want to listen on a particular network interface, put
;; it's IP address here (e.g. "192.132.95.151").  If 'nil', all 
;; available interfaces will be used.
(defparameter *interface* nil) ;; nil means all

(defparameter *default-umask* #o022) 
(defparameter *default-directory-mode* #o755)

;; This is the list of login names that are treated as anonymous FTP
;; users.  This parameter must always be a list, even if there is only
;; one login name that you want to treat as anonymous.  The list may
;; be empty if you don't want any login names to be anonymous.
(defparameter *anonymous-ftp-names* '("ftp" "anonymous"))

;; All *anonymous-ftp-names* will be mapped to this single 
;; *anonymous-ftp-account name.  This account must exist in /etc/passwd
;; and must have a proper home directory (see the README file).
(defparameter *anonymous-ftp-account* "ftp")

;; *restricted-users* is a list of users who will be confined to their
;; home directories (and deeper) once they successfully login in.
;; Don't overestimate the security of this feature.  See the README file
;; for details.

;; If this parameter is 'nil', no users are restricted.  

;; If this parameter is 't', then all users are restricted except for
;; those listed in *unrestricted-users*.
(defparameter *restricted-users* nil)

;; If *restricted-users* is 't', this is the list of users who are excluded
;; from restriction.
(defparameter *unrestricted-users* nil)

;; If this file exists in the home directory of a user when logging it,
;; it is transmitted.
(defparameter *welcome-msg-file* "welcome.msg")

;; If the file exists in any directory a user changes to, it is transmitted.
;; This only happens once per directory for a given connection.
(defparameter *message-file* ".message")

;; If *quarantine-anonymous-uploads* is non-nil, then all uploads by
;; anonymous accounts will be quarantined.  This means that they will
;; have their mode bits set to 000 (no read, no write, no execute, by
;; anyone, including the owner).  This will help prevent your FTP server
;; from unwittingly becoming a warez site.   Keep in mind that this option
;; does not prevent uploads.  It just prevents people from downloading
;; the uploaded files until you change the mode bits on the file.

(defparameter *quarantine-anonymous-uploads* t)

;; These options control various restrictions on anonymous users. 
;; IMPORTANT:  If *quarantined-anonymous-uploads* is non-nil, then
;; *anonymous-chmod-disabled* should be non-nil as well, otherwise 
;; anonymous users will be able to change the mode bits on their
;; uploaded files themselves.

(defparameter *anonymous-chmod-disabled* t) 
(defparameter *anonymous-rename-disabled* t)
(defparameter *anonymous-mkdir-disabled* t)
(defparameter *anonymous-rmdir-disabled* t)
(defparameter *anonymous-delete-disabled* t)

;; Put longest extensions first (due to the way matching is done)
;; Vectors are used so that no intermediate shell is spawned by
;; run-shell-command.  This is very important for security.
;; See the 'Security notes' section of the README file for additional
;; information regarding conversions security.
(defparameter *conversions*
    '((".tar.bz2" . #.(vector "/bin/tar" "cjf" "-"))
      (".tar.gz" . #("/bin/tar" "czf" "-"))
      (".tar.Z" . #("/bin/tar" "cZf" "-"))
      (".tar" . #("/bin/tar" "cf" "-"))
      (".zip" . #("/bin/zip" "-qq" "-r" "-"))
      (".bz2" . #("/bin/bzip2" "-c"))
      (".gz" . #("/bin/gzip" "-9" "-c"))
      (".Z" . #("/bin/compress" "-c"))))

(defparameter *debug* nil)

;; End of configuration variables.
