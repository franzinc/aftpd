;; $Id: ftpd.cl,v 1.19 2002/02/15 01:28:45 layer Exp $

(in-package :user)

(defvar *ftpd-version* "1.0.11")

(eval-when (compile)
  (proclaim '(optimize (safety 1) (space 1) (speed 3) (debug 2))))

;; Location of the configuration files (which one can use to 
;; override the rest of these parameters).
(defparameter *configfile* "/etc/aftpd.cl")

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

;; If you only want to listen on a particular network interface, put
;; it's IP address here (e.g. "192.132.95.151").  If 'nil', all 
;; available interfaces will be used.
(defparameter *interface* nil) ;; nil means all

(defparameter *default-umask* #o022) 

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

;; If *quarantine-anonymous-uplodas* is non-nil, then all uploads by
;; anonymous accounts will be quarantined.  This means that they will
;; have their mode bits set to 000 (no read, no write, no execute, by
;; anyone, including the owner).  This help prevent your FTP server
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

(ff:def-foreign-call fork () :strings-convert nil :returning :int)
(ff:def-foreign-call wait () :strings-convert nil :returning :int)
(ff:def-foreign-call waitpid () :strings-convert nil :returning :int)
(ff:def-foreign-call kill () :strings-convert nil :returning :int)
(ff:def-foreign-call (unix-crypt "crypt") () :strings-convert t 
		     :returning :unsigned-int)
(ff:def-foreign-call setgid () :strings-convert nil :returning :int)
(ff:def-foreign-call setegid () :strings-convert nil :returning :int)
(ff:def-foreign-call setuid () :strings-convert nil :returning :int)
(ff:def-foreign-call seteuid () :strings-convert nil :returning :int)
(ff:def-foreign-call geteuid () :strings-convert nil :returning :unsigned-int)
(ff:def-foreign-call initgroups () :strings-convert t :returning :int)
(ff:def-foreign-call getpid () :strings-convert nil :returning :unsigned-int)
(ff:def-foreign-call umask () :strings-convert nil :returning :unsigned-int)
(ff:def-foreign-call (unix-chdir "chdir") () :strings-convert t
		     :returning :int)
(ff:def-foreign-call chroot () :strings-convert t :returning :int)
(ff:def-foreign-call unlink () :strings-convert t :returning :int)
(ff:def-foreign-call (unix-strerror "strerror") () :strings-convert t 
		     :returning :unsigned-int)
(ff:def-foreign-call (unix-ctime "ctime") () :strings-convert nil 
		     :returning :unsigned-int)
(ff:def-foreign-call localtime () :strings-convert nil
		     :returning :unsigned-int)
(ff:def-foreign-call gmtime () :strings-convert nil
		     :returning :unsigned-int)
(ff:def-foreign-call strftime () :strings-convert t
		     :returning :unsigned-int)
(ff:def-foreign-call (unix-time "time") () :strings-convert nil
		     :returning :unsigned-int)
(ff:def-foreign-call rename () :strings-convert t
		     :returning :int)
(ff:def-foreign-call chmod () :strings-convert t 
		     :returning :int)
(ff:def-foreign-call setpgrp () :strings-convert nil 
		     :returning :int)
(ff:def-foreign-call (unix-open "open") () :strings-convert t
		     :returning :int)
(ff:def-foreign-call (unix-close "close") () :strings-convert nil
		     :returning :int)
(ff:def-foreign-call ioctl () :strings-convert t :returning :int)

;; add to a unix time to get a universal time.
;; subtract from a universal time to get a unix time.
(defconstant *unix-time-to-universal-time* 2208988800)

(eval-when (compile load eval)
  (defparameter *extra-files*
      '("passwd" "eol" "posix-lock")))

(eval-when (compile)
  (dolist (source *extra-files*)
    (compile-file-if-needed
     (concatenate 'string source ".cl"))))

(eval-when (compile load eval)
  (dolist (file *extra-files*)
    (load (concatenate 'string file ".fasl")))
  (require :acldns)
  (use-package :util.passwd))

(eval-when (compile load eval)
  ;;; cox recommendation
  (defparameter *extfcrlf* 
      (find-composed-external-format :e-crlf (crlf-base-ef :latin1))))


;; Good for Solaris and Linux
(eval-when (load eval)
  (load "libcrypt.so"))

(defclass client () 
  ((sock :initarg :sock :reader client-sock)
   (type :initform :ascii-nonprint :accessor client-type)
   (mode :initform :stream)
   (stru :initform :file)
   (logged-in :initform nil :accessor logged-in)
   (attempts :initform 0 :accessor attempts)
   (user :initform nil :accessor user)
   (pwent :initform nil :accessor pwent)
   (anonymous :initform nil :accessor anonymous)
   (pwd :accessor pwd)
   (addr :initform nil :accessor dataport-addr)
   (port :initform nil :accessor dataport-port)
   (pasv :initform nil :accessor pasv) ;; holds pasv server socket
   (open :initform nil :accessor dataport-open)
   (dsock :initform nil :accessor dataport-sock) ;; holds a connected socket
   (restart :initform 0 :accessor client-restart)
   (umask :initform *default-umask* :accessor client-umask)
   (rename-from :initform nil :accessor rename-from)
   (message-seen :initform (make-hash-table :test #'equal)
		 :accessor message-seen)
   (restricted :initform nil :accessor restricted)
   ))


(eval-when (compile load eval)
  (defstruct cmd
    command
    implemented
    must-be-logged-in
    handler)
  
  (defparameter *cmds* (make-hash-table :test #'equalp))
  (dolist 
      (entry 
	  '(;; Login
	    ("user" t nil cmd-user)
	    ("pass" t nil cmd-pass)
	    ("acct" nil nil nil)
	    
	    ;; Logout
	    ("rein" nil nil nil)
	    ("quit" t nil cmd-quit)

	    ;; Transfer parameters 
	    ("port" t t cmd-port)
	    ("pasv" t t cmd-pasv)
	    ("mode" t t cmd-mode)
	    ("type" t t cmd-type)
	    ("stru" t t cmd-stru)

	    ;; File action commands 
	    ("allo" t t cmd-allo)
	    ("rest" t t cmd-rest)
	    ("stor" t t cmd-stor)
	    ("stou" nil t cmd-stou)
	    ("retr" t t cmd-retr)
	    ("list" t t cmd-list)
	    ("nlst" t t cmd-nlst)
	    ("appe" t t cmd-appe)
	    ("rnfr" t t cmd-rnfr)
	    ("rnto" t t cmd-rnto)
	    ("dele" t t cmd-dele)
	    ("rmd" t t cmd-rmd)
	    ("xrmd" t t cmd-rmd)
	    ("mkd" t t cmd-mkd)
	    ("xmkd" t t cmd-mkd)
	    ("pwd" t t cmd-pwd)
	    ("xpwd" t t cmd-pwd)
	    ("abor" t t cmd-abor)
	    ("cwd" t t cmd-cwd)
	    ("xcwd" t t cmd-cwd)
	    ("cdup" t t cmd-cdup)
	    ("xcup" t t cmd-cdup)
	    ("smnt" nil nil nil)
	    ("mdtm" t t cmd-mdtm)
	    ("size" t t cmd-size)
	    
	    ;; Informational commands
	    ("syst" t t cmd-syst)
	    ("stat" t t cmd-stat)
	    ("help" t t cmd-help)
	    
	    ;; Miscellaneous commands
	    ("site" t t cmd-site)
	    ("noop" t t cmd-noop)))
    (setf (gethash (first entry) *cmds*)
      (make-cmd
       :command (first entry)
       :implemented (second entry)
       :must-be-logged-in (third entry)
       :handler (fourth entry)))))

(defparameter *sitecmds*
    '(("chmod" . site-chmod)
      ("umask" . site-umask)))

(defparameter *logstream* nil)
(defparameter *xferlogstream* nil)

(defun standalone-main ()
  (let ((serv (socket:make-socket :connect :passive 
				  :local-host *interface*
				  :local-port *ftpport*
				  :reuse-address t)))
    (socket:configure-dns :auto t)
    (unwind-protect
	(loop
	  (let ((client (handler-case (socket:accept-connection serv)
			  (interrupt-signal ()
			    (exit))
			  (error ()
			    nil))))
	    (if client
		(spawn-client client serv))))
      ;; cleanup forms
      (close serv))))

;; In case I can't get a decent SIGCHLD handler.

(defmacro with-fork (pidsym parent-form child-form)
  `(let ((,pidsym (fork)))
     (cond
      ((< ,pidsym 0)
       (error "fork failed!"))
      ((> ,pidsym 0) ;; parent
       ,parent-form)
      ((= ,pidsym 0) ;; child
       ,child-form))))
  
(defmacro with-orphaned-child (&body body)
  (let ((pidsym (gensym))
	(pidsym2 (gensym)))
    `(with-fork ,pidsym
       ;; parent form
       (waitpid ,pidsym 0 0) ;; reap child
       ;; child form
       (with-fork ,pidsym2
	 ;; parent exits to orphan child.  (init will reap it)
	 (exit t :no-unwind t :quiet t)
	 ;; child does what it needs to do.
	 (progn
	   ,@body
	   (exit t :no-unwind t :quiet t))))))

(defun spawn-client (sock serv)
  (with-orphaned-child 
      (close serv) ;; child doesn't need it.
      (add-pid)
      (unwind-protect
	  (ftpd-main sock)
	(ignore-errors (close sock))))
  ;; child never gets here.  Parent does.
  (close sock)) ;; main ftp server doesn't need this

(defmacro with-pids-file ((stream-sym pids-list-sym) &body body)
  `(with-open-file (,stream-sym *pidsfile*
		    :if-exists :overwrite
		    :if-does-not-exist :create
		    :direction :io)
     (util.posix-lock:with-stream-lock (,stream-sym)
       (let ((,pids-list-sym (read ,stream-sym nil nil)))
	 ,@body
	 (file-position ,stream-sym 0)
	 (format ,stream-sym "~A~%" ,pids-list-sym)))))
     
(defun add-pid ()
  (with-pids-file (f pids)
    (pushnew (getpid) pids)))

;; returns the number of active pids.  
;; also updates the pids file w/ the active list.
(defun probe-pids-file ()
  (let (active)
    (with-pids-file (f pids)
      (dolist (pid pids)
	(if (= 0 (kill pid 0))
	    (push pid active)))
      (setf pids active))
    (length active)))

;;; C library utils

(defun strerror (errno)
  (if (null errno)
      "Unknown error"
    (without-interrupts
      (native-to-string (unix-strerror errno)))))

(defun crypt (string salt)
  (without-interrupts
   (native-to-string (unix-crypt string salt))))


;;;


(defparameter *outlinestream* 'outlinestream-not-bound)

;; never call outline w/ a first argument that is anything
;; but a format string.  This macro checks for that situation
;; to be safe.
(defmacro outline (format-string &rest args)
  (let ((ressym (gensym)))
    (when (not (stringp format-string))
      (error "Crikey, format-string is not a string constant: ~s."
	     format-string))
    `(let ((,ressym (format nil ,format-string ,@args)))
       (if (eq *debug* :verbose)
	   (ftp-log "~A~%" ,ressym))
       (write-string ,ressym *outlinestream*)
       (write-char #\return *outlinestream*)
       (write-char #\newline *outlinestream*)
       (force-output *outlinestream*))))

;;; 

(defun spawn-command (cmdvec)
  (if (not (vectorp cmdvec))
      (error "Ack!! non-vector passed to spawn-command"))
  (multiple-value-bind (stdout stderr pid)
      (run-shell-command cmdvec
			 :input "/dev/null"
			 :output :stream
			 :error-output :stream
			 :wait nil)
    (mp:process-run-function "stderr reader" 'stderr-reader stderr)
    (values stdout pid)))

(defun stderr-reader (stderr)
  (unwind-protect
      (let (line)
	(while (setf line (read-line stderr nil nil))
	       (ftp-log "~A~%" line)))
    (ignore-errors (close stderr))))

(defmacro with-external-command ((streamvar cmdvec) &body body)
  (let ((pidvar (gensym)))
    `(multiple-value-bind (,streamvar ,pidvar) (spawn-command ,cmdvec)
       (unwind-protect (progn ,@body)
	 (close ,streamvar)
	 (sys:reap-os-subprocess :pid ,pidvar)))))

;;;

(defconstant *telnetIAC* 255)
;;(defconstant *telnetIP* 244)
;;(defconstant *telnetSynch* 242)

(defparameter *maxline* 5000)

(defun get-request (client)
  (let ((sock (client-sock client))
	(buffer (make-string *maxline*))
	(pos 0)
	lastchar
	gotiac
	longline
	char)
    (mp:with-timeout (*idletimeout* :timeout)
      (loop
	(if (>= pos *maxline*)
	    (progn
	      (setf longline t)
	      (setf pos 0)))

	(setf char 
	  (handler-case (read-char sock)
	    (error ()
	      nil)))

	(if (null char)
	    (return :eof))
	
	(if (and (char= char #\newline) (eq lastchar #\return))
	    (return (if longline 
			:line-too-long
		      (subseq buffer 0 (1- pos)))))

	;;; XXX -- telnet sequences.  Stripped and ignored.
	;;; XXX -- (two-byte sequences, only)
	(if* gotiac
	   then
		(setf gotiac nil)
		(if (= (char-code char) *telnetIAC*)
		    (progn
		      ;; escaped #xff
			      (setf (schar buffer pos) char)
		      (incf pos)
		      (setf lastchar char)))
	   else
		(if (= (char-code char) *telnetIAC*)
		    (setf gotiac t)
		  (progn
		    ;; Regular stuff
		    (setf (schar buffer pos) char)
		    (incf pos)
		    (setf lastchar char))))))))

(defun ftpd-main (sock)
  (if (probe-file *configfile*)
      (load *configfile*))
  (open-logs)
  (ftp-log "Connection made from ~A.~%"
	   (socket:ipaddr-to-dotted 
	    (socket:remote-host sock)))
  (let ((client (make-instance 'client :sock sock))
	(*outlinestream* sock)
	(*locale* (find-locale :c))
	(*print-pretty* nil))
    (handler-case
	(progn
	  (umask (client-umask client))
	  (outline "220 ~A" *banner*)
	  (loop
	    (let ((req (get-request client)))
	      (if (eq req :eof)
		  (return (cleanup client)))
	      (if* (eq req :timeout)
		 then
		      (ignore-errors ;; in case the connection disappeared
		       (outline "421 Timeout: closing control connection."))
		      (return (cleanup client)))
	      (if (eq req :line-too-long)
		  (outline "500 Command line too long! Request ignored")
		(if (eq (dispatch-cmd client req) :quit)
		    (return (cleanup client)))))))
      (error (c)
	(ignore-errors ;; in case the connection disappeared.
	 (outline "421 Error: ~A -- closing control connection."
		  (substitute #\space #\newline (format nil "~A" c))))
	(ftp-log "Error: ~A~%" c))))
  (close-logs))
  
(defun dispatch-cmd (client cmdstring)
  (block nil
    (let ((spacepos (position #\space cmdstring))
	  cmdname
	  entry)
      (if (null spacepos)
	  (setf cmdname cmdstring)
	(setf cmdname (subseq cmdstring 0 spacepos)))
      
      (if (and (not (anonymous client)) 
	       (equalp cmdname "pass"))
	  (ftp-log "~A: PASS XXXXXX~%"
		  (socket:ipaddr-to-dotted 
		   (socket:remote-host (client-sock client))))
	(ftp-log "~A: ~A~%"
		(socket:ipaddr-to-dotted 
		 (socket:remote-host (client-sock client)))
		cmdstring))
      
      (setf entry (gethash cmdname *cmds*))
      (if (null entry)
	  (return (outline "500 '~A': command not understood." cmdstring)))
      (if (not (cmd-implemented entry))
	  (return (outline "502 ~A command not implemented." cmdname)))
      (if (and (cmd-must-be-logged-in entry)
	       (not (logged-in client)))
	  (return (outline "530 Please login with USER and PASS.")))
      (funcall (cmd-handler entry) client 
	       (if spacepos
		   (subseq cmdstring (1+ spacepos))
		 "")))))

(defun cleanup (client)
  (ftp-log "Client from ~A disconnected.~%"
	  (socket:ipaddr-to-dotted
	   (socket:remote-host (client-sock client))))
  (cleanup-data-connection client))

(defmacro with-root-privs (() &body body)
  (let ((oldidsym (gensym)))
    `(let ((,oldidsym (geteuid)))
       (if (not (= 0 (seteuid 0)))
	   (error "Failed to recover root privs"))
       (unwind-protect
	   (progn
	     ,@body)
	 (if (not (= 0 (seteuid ,oldidsym)))
	     (error "Failed to reset regular user privs"))))))

(defun ftp-chdir (dir)
  (if (= 0 (unix-chdir dir))
      (setf *default-pathname-defaults* 
	(pathname (concatenate 'string dir "/")))
    nil))

(defun cmd-quit (client cmdtail)
  (declare (ignore cmdtail client))
  (outline "221 Goodbye.")
  :quit)

(defun cmd-user (client user)
  (block nil
    (if (logged-in client)
	(return (outline "530 Already logged in.")))

    (setf (anonymous client) nil)
    
    (if (and (member user *anonymous-ftp-names* :test #'equalp)
	     (lookup-account *anonymous-ftp-account*))
	(progn
	  (setf user *anonymous-ftp-account*)
	  (setf (anonymous client) t)))
    
    (setf (user client) user)
    
    (setf (pwent client) (lookup-account user))
    ;; XXX - Doesn't allow no-password logins.
    (if (anonymous client)
	(outline 
	 "331 Guest login ok, send your complete e-mail address as password.")
      (outline "331 Password required for ~A." user))))

;; XXX -- could use PAM
(defun lookup-account (user)
  (block nil
    (let ((pwent (get-pwent-by-name user)))
      (if (null pwent)
	  (return nil))
      (if (string= (pwent-passwd pwent) "x")
	  (let ((spent (get-spent-by-name user)))
	    (if spent
		(setf (pwent-passwd pwent) (spent-passwd spent)))))
      pwent)))

(defun cmd-pass (client pass)
  (block nil
    (let ((pwent (pwent client)))
      (if (logged-in client)
	  (return (outline "530 Already logged in.")))
      (if (null (user client))
	  (return (outline "503 Login with USER first.")))

      (if* (and *maxusers* (> (probe-pids-file) *maxusers*))
	 then
	      (dump-msg client "530" *toomanymsg*)
	      (outline "530 Connection limit exceeded.")
	      (ftp-log "Connection limit (~D) exceeded.~%" *maxusers*)
	      (return :quit))
      
      (if* (anonymous client)
	 then
	      (setf (anonymous client) pass)
	 else
	      (if (or (null pwent)
		      (not (string= (pwent-passwd pwent)
				    (crypt pass (pwent-passwd pwent)))))
		  (return
		    (progn
		      (setf (user client) nil)
		      (setf (pwent client) nil)		  
		      (sleep *badpwdelay*)
		      (outline "530 Login incorrect.")
		      (incf (attempts client))
		      (if (>= (attempts client) *max-password-attempts*)
			  :quit)))))

      ;; Successful authentication
      (ftp-log "User ~A logged in.~%" (user client))
      (setf (pwd client) (pwent-dir pwent))

      (if* (anonymous client)
	 then
	      (anonymous-setup client)
	 else
	      ;; If *restricted-users* is 't', then all users are restricted except for those
	      ;; in the *unrestricted-users* list.   Otherwise, a user is restricted if he/she
	      ;; is listed in *restricted-users*.
	      
	      (if* (eq *restricted-users* t)
		 then
		      (if (member (user client) *unrestricted-users* :test #'string=)
			  (setf (restricted client) nil)
			(setf (restricted client) t))
		 else
		      (if (member (user client) *restricted-users* :test #'string=)
			  (setf (restricted client) t))))
      
      ;; Set up
      (if (not (= 0 (setegid (pwent-gid pwent))))
	  (progn
	    (ftp-log "Failed to setegid(~D)~%" (pwent-gid pwent))
	    (outline "421 Local configuration error.")
	    (return :quit)))
      
      (if (not (= 0 (initgroups (user client) (pwent-gid pwent))))
	  (progn
	    (ftp-log "Failed to initgroups~%")
	    (outline "421 Local configuration error.")
	    (return :quit)))
      
      (if (not (= 0 (seteuid (pwent-uid pwent))))
	  (progn
	    (ftp-log "Failed to seteuid(~D)~%" (pwent-uid pwent))
	    (outline "421 Local configuration error.")
	    (return :quit)))
      
      (if (null (ftp-chdir (pwent-dir pwent)))
	  (progn
	    (ftp-log "Failed to chdir(~A)~%" (pwent-dir pwent))
	    
	    ;; Anonymous/restricted users have no alternative
	    (if (or (anonymous client) (restricted client))
		(progn
		  (outline "421 Local configuration error.")
		  (return :quit)))
	    
	    (if (not (ftp-chdir "/"))
		(progn
		  (ftp-log "Failed to chdir(/)~%")
		  (outline "421 Local configuration error.")
		  (return :quit))
	      (progn
		(setf (pwent-dir pwent) "/")
		(outline "230-No directory! Logging in with home=/")))))

      (setf (logged-in client) t)
      (cleanup-data-connection client) 
      (dump-msg client "230" *welcome-msg-file*)
      (outline "230 User ~A logged in." (user client)))))

(defun anonymous-setup (client)
  (block nil
    (let ((pwent (pwent client)))
      (if (null (ftp-chdir (pwent-dir pwent)))
	  (progn
	    (ftp-log "Failed to chdir(~A)~%" (pwent-dir pwent))
	    (outline "421 Local configuration error.")
	    (return nil)))
      (if (not (= 0 (chroot (pwent-dir pwent))))
	  (progn
	    (ftp-log "Failed to chroot(~A)~%" (pwent-dir pwent))
	    (outline "421 Local configuration error.")
	    (return nil)))
      (setf (pwent-dir pwent) "/")
      (setf (pwd client) "/")
      t)))

(defmacro ftp-with-open-file ((streamsym errsym path &rest rest) &body body)
  `(let (,errsym)
     (declare (ignore-if-unused ,errsym))
     (let ((,streamsym 
	    (handler-case (open ,path ,@rest)
	      (file-error (c)
		(setf ,errsym (excl::file-error-errno c))
		nil))))
       (unwind-protect (progn ,@body)
	 (if ,streamsym
	     (close ,streamsym))))))

(defun dump-msg (client code file)
  (declare (ignore client))
  (block nil
    (if (or (null file)
	    (null (probe-file file)))
	(return))
    (ftp-with-open-file 
     (f errno file)
     (if f
	 (let (line)
	   (while (setf line (read-line f nil nil))
		  (outline "~A-~A" code line)))))))


(defun cmd-pwd (client cmdtail)
  (declare (ignore cmdtail))
  (outline "257 \"~A\" is current directory."
	   (pwd client)))

(defun cmd-noop (client cmdtail)
  (declare (ignore client cmdtail))
  (outline "200 NOOP command successful."))

(defun cmd-port (client cmdtail)
  (block nil
    (multiple-value-bind (matched whole a b c d e f)
	(match-regexp 
	 "\\([0-9]+\\),\\([0-9]+\\),\\([0-9]+\\),\\([0-9]+\\),\\([0-9]+\\),\\([0-9]+\\)"
	 cmdtail)
      (declare (ignore whole))
      (if (not matched)
	  (return (outline "500 'PORT ~A': command not understood." cmdtail)))
      (setf a (parse-integer a))
      (setf b (parse-integer b))
      (setf c (parse-integer c))
      (setf d (parse-integer d))
      (setf e (parse-integer e))
      (setf f (parse-integer f))
      (let ((addr (logior (ash a 24) (ash b 16) (ash c 8) d))
	    (port (logior (ash e 8) f)))
	(if (or (not (= addr (socket:remote-host (client-sock client))))
		(< port 1024))
	    (return
	      (progn
		(ftp-log "Client from ~A tried to set PORT ~A:~A~%"
			(socket:ipaddr-to-dotted 
			 (socket:remote-host (client-sock client)))
			(socket:ipaddr-to-dotted addr)
			port)
		(outline "500 Illegal PORT Command"))))
	(cleanup-data-connection client)
	(setf (dataport-addr client) addr)
	(setf (dataport-port client) port)
	(setf (pasv client) nil)
	(outline "200 PORT command successful.")))))

(defun cmd-pasv (client cmdtail)
  (declare (ignore cmdtail))
  (cleanup-data-connection client)
  (let (port sock)
    (while (null sock)  
	   ;; XXX -- this could theoretically loop forever.  Need a loop limiter
	   (setf port (+ (car *pasvrange*)
			 ;;  XXX -- (random) always returns the same sequence of numbers.
			 ;; XXX -- need to seed it w/ some random data (/dev/urandom)
			 (random (1+ (- (cdr *pasvrange*) (car *pasvrange*))))))
	   (handler-case (setf sock (socket:make-socket
				     :type :hiper
				     :connect :passive
				     :local-host *interface*
				     :local-port port))
	     (socket-error (c)
	       (if (not (eq (stream-error-identifier c) :address-in-use))
		   (signal c)
		 nil))))
    (setf (pasv client) sock)
    (let ((addr (socket:local-host (client-sock client))))
      (outline "227 Entering Passive Mode (~D,~D,~D,~D,~D,~D)"
	       (logand (ash addr -24) #xff)
	       (logand (ash addr -16) #xff)
	       (logand (ash addr -8) #xff)
	       (logand addr #xff)
	       (logand (ash port -8) #xff)
	       (logand port #xff)))))

(defun cmd-type (client cmdtail)
  (block nil
    (let ((params (delimited-string-to-list cmdtail " ")))
      (cond
       ((or (equalp cmdtail "i") (equalp cmdtail "image"))
	(setf (client-type client) :image)
	(outline "200 Type set to I."))
       ((equalp cmdtail "e")
	(outline "504 Type E not implemented."))
       ((or (equalp (first params) "a") (equalp (first params) "ascii"))
	(if (and (second params) 
		 (not (equalp (second params) "n")))
	    (return (outline "504 Form must be N.")))
	(setf (client-type client) :ascii-nonprint)
	(outline "200 Type set to A."))
       ((equalp (first params) "l")
	(if (and (second params) 
		 (not (string= (second params) "8")))
	    (return (outline "504 Byte size must be 8.")))
	(setf (client-type client) :local)
	(outline "200 Type set to L (byte size 8)."))
       (t
	(outline "500 'TYPE ~A': command not understood." cmdtail))))))

(defun cmd-stru (client cmdtail)
  (declare (ignore client))
  (if (not (member cmdtail '("f" "r" "p") :test #'equalp))
      (outline "500 'STRU ~A': command not understood." cmdtail)
    (if (not (equalp cmdtail "f"))
	(outline "504 Unimplemented STRU type.")
      (outline "200 STRU F ok."))))

(defun cmd-mode (client cmdtail)
  (declare (ignore client))
  (if (not (member cmdtail '("s" "b" "c") :test #'equalp))
      (outline "500 'MODE ~A': command not understood." cmdtail)
    (if (not (equalp cmdtail "s"))
	(outline "504 Unimplemented MODE type.")
      (outline "200 MODE S ok."))))

(defun cmd-rest (client cmdtail)
  (block nil
    (let ((point (ignore-errors (parse-integer cmdtail))))
      (if (null point)
	  (return (outline "500 'REST ~A: command not understood." cmdtail)))
      (if (< point 0)
	  (return (outline "501 'REST ~A: invalid parameter." cmdtail)))
      (setf (client-restart client) point)
      (outline "350 Restarting at ~D. Send STOR or RETR to initiate transfer."
	       point))))

(defun cmd-allo (client cmdtail)
  (declare (ignore client cmdtail))
  (outline "202 ALLO command ignored."))

;; XXX -- pretty useless I don't support asychronous requests.
(defun cmd-abor (client cmdtail)
  (declare (ignore cmdtail))
  (cleanup-data-connection client)
  (outline "225 ABOR command successful."))
  

(defun data-connection-prepared-p (client)
  (or (dataport-addr client)
      (pasv client)))

(defun cleanup-data-connection (client)
  (if (dataport-open client)
      (progn
	(ignore-errors (close (dataport-sock client)))
	(setf (dataport-sock client) nil)
	(setf (dataport-open client) nil)))
  (if (pasv client)
      (progn
	(ignore-errors (close (pasv client)))
	(setf (pasv client) nil)))
  (setf (dataport-addr client) nil)
  (setf (dataport-port client) nil))


;; Drops connections made by other hosts.
(defun accept-pasv-connection-from-client (client)
  (loop
    (let ((newsock (ignore-errors (socket:accept-connection (pasv client)))))
      (if newsock
	  (if (not (= (socket:remote-host newsock)
		      (socket:remote-host (client-sock client))))
	      (progn
		(ftp-log "Non-client connection to PASV port ~A:~A made by ~A.~%"
			(socket:ipaddr-to-dotted 
			 (socket:local-host (client-sock client)))
			(socket:local-port (pasv client))
			(socket:ipaddr-to-dotted
			 (socket:remote-host newsock)))
		(ignore-errors (close newsock)))
	    (return newsock))))))

;; This is covered by the with-timeout in establish-data-connection
(defun make-active-connection (client)
  (handler-case 
      (with-root-privs ()
	(socket:make-socket :remote-host (dataport-addr client)
			    :remote-port (dataport-port client)
			    :local-host *interface*
			    :local-port *ftpdataport* 
			    :reuse-address t
			    :type :hiper))
    (error (c)
      (ftp-log "make-active-connection: make-socket failed; ~A~%" c)
      nil)))

(defun establish-data-connection (client)
  (block nil
    (setf (dataport-sock client)
      (mp:with-timeout (*connecttimeout* :timeout)
	(if (pasv client)
	    (accept-pasv-connection-from-client client)
	  (make-active-connection client))))
    (if (null (dataport-sock client))
	(progn
	  (outline "425 Can't open data connection.")
	  (return nil)))
    (if (eq (dataport-sock client) :timeout)
	(progn
	  (outline "425 Can't open data connection.  Timed out.")
	  (return nil)))

    (socket:socket-control 
     (dataport-sock client)
     :read-timeout *transfertimeout*
     :write-timeout *transfertimeout*)
    
    (setf (dataport-open client) t)))

(defun cmd-retr (client file)
  (block nil
    (let ((fullpath (make-full-path (pwd client) file)))

      (if (and (restricted client)
	       (out-of-bounds-p client fullpath))
	  (return (outline "550 ~A: Permission denied." file)))

      (if (null (data-connection-prepared-p client))
	  (return (outline "452 No data connection has been prepared.")))
      
      (if (not (probe-file fullpath))
	  (multiple-value-bind (conv realname)
	      (conversion-match file)
	    (if conv
		(return (start-conversion client conv realname)))
	    (return (outline "550 ~A: No such file or directory." file))))

      (if (not (eq :file (excl::filesys-type fullpath)))
	  (return (outline "550 ~A: not a plain file." file)))	   
      
      (ftp-with-open-file 
       (f errno fullpath)
       (if (null f)
	   (return (outline "550 ~A: ~A" file (strerror errno))))

       ;; XXX -- this is only correct for binary files.
       (let ((res (ignore-errors 
		   (file-position f (client-restart client)))))
	 (setf (client-restart client) 0)
	 (if (null res)
	     (return (outline "550 ~A: RETR (with REST) failed." file))))
		    
       (transmit-stream client f fullpath)))))
    
;; This should be called after 'path' has been verified not to exist.
(defun conversion-match (path)
  (let ((pathlen (length path))
	ext
	extlen)
    (dolist (extcons *conversions*)
      (setf ext (car extcons))
      (setf extlen (length ext))
      (if (and (> pathlen extlen)
	       (string= (subseq path (- pathlen extlen)) ext))
	  (return (values (cdr extcons) (subseq path 0 (- pathlen extlen))))))))

(defun start-conversion (client conversionvec file)
  (block nil
    (if (not (eq (client-type client) :image))
	(return 
	  (outline "550 This is a BINARY file, using ASCII mode to transfer will corrupt it.")))
    (if (not (= 0 (client-restart client)))
	(return
	  (outline "550 REST not allowed with conversions.")))
    (let ((cmdvec (concatenate 'vector 
		    (vector (aref conversionvec 0)) ;; duplicate first entry
		    conversionvec
		    (vector file))))
      (with-external-command (stream cmdvec)
	(transmit-stream client stream (aref cmdvec 0))))))

(defun transmit-stream (client stream name) 
  (block nil
    (if (null (establish-data-connection client))
	(return))
    
    (outline "150 Opening ~A mode data connection for ~A."
	     (if (eq (client-type client) :image)
		 "BINARY" "ASCII")
	     name)

    (if (handler-case (dump-file client stream)
	  (socket-error (c)
	    (if (or (eq (stream-error-identifier c) :read-timeout)
		    (eq (stream-error-identifier c) :write-timeout))
		(outline "426 Data transfer timeout.")
	      (outline "426 Data connection: Broken pipe."))
	    nil)
	  (error (c)
	    (let ((*print-pretty* nil))
	      (outline "426 Error: ~A"
		       (substitute #\space #\newline (format nil "~A" c))))
	    nil))
	(outline "226 Transfer complete."))

    (xfer-log client name :retr 
	      (excl::socket-bytes-written (dataport-sock client)))
    
    (cleanup-data-connection client)))

(defun dump-file (client f)
  (if (eq (client-type client) :ascii-nonprint)
      (dump-file-ascii client f)
    (dump-file-binary client f))
  t)
  
(defun dump-file-ascii (client f)
  (let ((inbuffer (make-string 32768))
	(outbuffer (make-array 65536 :element-type '(unsigned-byte 8)))
	(sock (dataport-sock client))
	got)
    (while (not (= 0 (setf got (read-sequence inbuffer f :partial-fill t))))
	   (multiple-value-bind (ignore count)
	       (string-to-octets inbuffer 
				 :null-terminate nil 
				 :mb-vector outbuffer
				 :end got
				 :external-format *extfcrlf*)
	     (declare (ignore ignore))
	     (write-complete-vector outbuffer count sock))))
  t)

(defun dump-file-binary (client f)
  (let ((buffer (make-array 65536 :element-type '(unsigned-byte 8)))
	(sock (dataport-sock client))
	got)
    (while (not (= 0 (setf got (read-vector buffer f))))
	   (write-complete-vector buffer got sock)))
  t)

(defun write-complete-vector (vec end stream)
  (let ((pos 0)
	newpos)
    (while (< pos end)
	   (setf newpos (write-vector vec stream :start pos :end end))
	   (if (= newpos pos)
	       (error "write-vector failed"))
	   (setf pos newpos))))
      

(defun cmd-stor (client file)
  (store-common client file :supersede))

(defun cmd-appe (client file)
  (store-common client file :append))

(defmacro with-umask ((newumask) &body body)
  (let ((oldumasksym (gensym)))
    `(let ((,oldumasksym (umask ,newumask)))
       (unwind-protect
	   (progn ,@body)
	 (umask ,oldumasksym)))))

(defun store-common (client file if-exists)
  (block nil
    (let ((fullpath (make-full-path (pwd client) file)))
      
      (if (not (= 0 (client-restart client)))
	  (return (outline "452 REST > 0 not supported with STOR.")))
      
      (if (and (restricted client)
	       (out-of-bounds-p client fullpath))
	  (return (outline "550 ~A: Permission denied." file)))
      
      (if (null (data-connection-prepared-p client))
	  (return (outline "452 No data connection has been prepared.")))
      
      (with-umask ((if (and (anonymous client) *quarantine-anonymous-uploads*)
		       #o777 
		     (client-umask client)))
	(ftp-with-open-file 
	 (f errno fullpath
	    :direction :output
	    :if-exists if-exists
	    :if-does-not-exist :create)
	 (if (null f)
	     (return (outline "550 ~A: ~A" file (strerror errno))))
	 
	 (if (null (establish-data-connection client))
	     (return))
	 
	 (outline "150 Opening ~A mode data connection for ~A."
		  (if (eq (client-type client) :ascii-nonprint)
		      "ASCII" "BINARY")
		  file)
	 
	 (if (handler-case (store-file client f)
	       (socket-error (c)
		 (if (or (eq (stream-error-identifier c) :read-timeout)
			 (eq (stream-error-identifier c) :write-timeout))
		     (outline "426 Data transfer timeout.")
		   (outline "426 Data connection: Broken pipe."))
		 nil)
	       (error (c)
		 (let ((*print-pretty* nil))
		   (outline "426 Error: ~A"
			    (substitute #\space #\newline (format nil "~A" c))))
		 nil))
	     (outline "226 Transfer complete."))

	 (xfer-log client fullpath :stor 
		   (excl::socket-bytes-read (dataport-sock client)))
	 
	 (cleanup-data-connection client))))))

(defun store-file (client out)
  (if (eq (client-type client) :ascii-nonprint)
      (store-file-ascii client out)
    (store-file-binary client out))
  t)

(defun store-file-ascii (client out)
  (let ((inbuffer (make-array 32768 :element-type '(unsigned-byte 8)))
	(outbuffer (make-string 32768))
	(sock (dataport-sock client))
	(startpos 0)
	got)
    (while (> (setf got (read-vector inbuffer sock :start startpos)) startpos)
	   (multiple-value-bind (string outbytes usedbytes)
	       (octets-to-string inbuffer 
				 :string outbuffer 
				 :external-format *extfcrlf*
				 :end got
				 :truncate t)
	     (declare (ignore string))
	     (write-string outbuffer out :end outbytes)
	     (setf startpos (- got usedbytes))
	     ;; move remaining bytes to the beginning of the vector
	     ;; (This should only be 0 or 1 bytes)
	     (dotimes (i startpos)
	       (setf (aref inbuffer i) (aref inbuffer (+ i usedbytes))))))
    ;; flush any trailing data
    (if startpos
	(write-string (octets-to-string inbuffer 
					:string outbuffer
					:external-format *extfcrlf*
					:end startpos
					:truncate nil)
		      out :end startpos))))

(defun store-file-binary (client out)
  (let ((in (dataport-sock client))
	(buffer (make-array 65536 :element-type '(unsigned-byte 8)))
	got)
    (while (not (= 0 (setf got (read-vector buffer in))))
	   (write-complete-vector buffer got out))))
    

(defun cmd-syst (client cmdtail)
  (declare (ignore cmdtail client))
  (outline "215 UNIX Type: L8"))

(defun cmd-cdup (client cmdtail)
  (declare (ignore cmdtail))
  (cmd-cwd client ".."))

(defun cmd-cwd (client cmdtail)
  (block nil
    (let ((newpwd (expand-tilde 
		   client 
		   (if (string= cmdtail "") "~" cmdtail))))

      (if (null newpwd)
	  (return (outline "550 Unknown user name after ~~")))
      
      (setf newpwd (make-full-path (pwd client) newpwd))

      (if (and (restricted client) 
	       (out-of-bounds-p client newpwd))
	  (return (outline "550 ~A: Permission denied." cmdtail)))
      
      (if (null (ftp-chdir newpwd))
	  (return (outline "550 ~A: Command failed." cmdtail)))
      
      (setf (pwd client) newpwd)
      
      (if *message-file*
	  (let ((msgfile (make-full-path newpwd *message-file*)))
	    (if (and (probe-file msgfile)
		     (not (gethash msgfile (message-seen client))))
		(progn
		  (setf (gethash msgfile (message-seen client)) t)
		  (ignore-errors 
		   (with-open-file (f msgfile)
		     (let (line)
		       (while (setf line (read-line f nil nil))
			      (outline "250-~A" line)))))))))
      
      (outline "250 ~S is the current directory." newpwd))))

;;; Returns nil if the user is unknown. 
(defun expand-tilde (client path)
  (block nil
    (if (not (match-regexp "^~" path))
	(return path))
    (let* ((slashpos (position #\/ path))
	   (name (subseq path 1 slashpos))
	   (dir (if (string= name "")
		    (pwent-dir (pwent client))
		  (let ((pwent (get-pwent-by-name name)))
		    (if (null pwent)
			(return nil)
		      (pwent-dir pwent))))))
      (if (null slashpos)
	  dir
	(concatenate 'string dir (subseq path slashpos))))))

(defun absolute-path-p (path)
  (and (not (string= path ""))
       (char= (schar path 0) #\/)))

(defun ensure-absolute-path (path)
  (if (not (absolute-path-p path))
      (error "path must be absolute!")))

(defun strip-trailing-slash (path)
  (if (string= path "/")
      "/"
    (replace-regexp path "^\\(.*\\)/$" "\\1")))

;; / ->  nil
;; /a -> (a)
;; /a/b -> (a b)
;; /a/b/ -> (a b)
;; Requires absolute path.
(defun path-to-list (path)
  (block nil
    (if (string= path "/")
	(return nil))
    (ensure-absolute-path path)
    (setf path (strip-trailing-slash path))
    (delimited-string-to-list (subseq path 1) #\/)))

;; handles . and .. and removes redundant slashes.
;; 'path' should be an absolute path
(defun canonicalize-path (path)
  (block nil
    (if (string= path "/")
	(return "/"))
    (setf path (path-to-list path))
    (let (res)
      (dolist (comp path)
	(cond
	 ((or (string= comp ".") (string= comp ""))
	  )
	 ((string= comp "..")
	  (pop res))
	 (t
	  (push comp res))))
      (setf res (reverse res))
      (if (null res)
	  (return "/"))
      (concatenate 'string "/" (list-to-delimited-string res #\/)))))


(defun make-full-path (pwd path)
  (block nil
    (if (absolute-path-p path)
	(return (canonicalize-path path)))
    (setf pwd (strip-trailing-slash pwd))
    (canonicalize-path
     (concatenate 'string
       pwd "/" path))))

;; /home/dir/ is within /home/dir.
;; 'parent' should not have a trailing slash.
;; both 'dir' and 'parent' should be absolute names
(defun within-dir-p (dir parent)
  (block nil
    (if (string= parent "/")
	(return t)) ;; everything is within the root directory
    (if (string= dir "/")
	(return nil)) ;; root dir isn't within anything else
    ;; strip trailing slash if there is one
    (setf dir (strip-trailing-slash dir))
    (let ((parentlen (length parent))
	  (dirlen (length dir)))
      (if (< dirlen parentlen)
	  (return nil))
      (string= parent (subseq dir 0 parentlen)))))
	  
(defun out-of-bounds-p (client path)
  (not (within-dir-p path (pwent-dir (pwent client)))))
  
;; attempts to glob switches as well.  That shouldn't be a big deal.
;; It might even work out in the interest of safety.
(defun list-common (client path default-options)
  (block nil
    (let ((options (glob path (pwd client))))
      (if (and (restricted client)
	       (some (lambda (opt) 
		       (out-of-bounds-p 
			client 
			(make-full-path (pwd client) opt))) options))
	  (return
	    (outline "550 Permission denied.")))
      
      (if (null (data-connection-prepared-p client))
	  (return (outline "452 No data connection has been prepared.")))
    
      (if (null (establish-data-connection client))
	  (return))
    
      (outline "150 Opening ASCII mode data connection for /bin/ls.")
    
      (let ((*outlinestream* (dataport-sock client)))
	(with-external-command (stream 
				(concatenate 'vector
				  #.(vector "/bin/ls" "/bin/ls")
				  default-options
				  options))
	  (let (line)
	    (while (setf line (read-line stream nil nil))
		   (outline "~A" line)))))
    
      (cleanup-data-connection client)
      (outline "226 Transfer complete."))))

(defun cmd-list (client path)
  (list-common client path #("-la")))

(defun cmd-nlst (client path)
  (list-common client path #()))
    
;; XXX -- according to the spec, this is supposed to work asynchronously.
;; XXX -- I'll probably never work on that.
(defun cmd-stat (client cmdtail)
  (block nil
    (if (not (string= cmdtail ""))
	(return (cmd-stat-file client cmdtail)))
    
    (outline "211-FTP server status:")
    (outline " Connected to ~A" 
	     (socket:ipaddr-to-dotted 
	      (socket:remote-host (client-sock client))))
    (outline " Logged in as ~A" (user client))
    (if (not (data-connection-prepared-p client))
	(outline " No data connection")
      (if (pasv client)
	  (outline " in Passive mode (~A:~A)"
		   (socket:ipaddr-to-dotted 
		    (socket:local-host (client-sock client)))
		   (socket:local-port (pasv client)))
	(outline " PORT (~A:~A)"
		 (socket:ipaddr-to-dotted (dataport-addr client))
		 (dataport-port client))))
    (outline "211 End of status")))

;; XXX - Doesn't do globbing.
(defun cmd-stat-file (client file)
  (block nil
    (if (and (restricted client)
	     (out-of-bounds-p client (make-full-path (pwd client) file)))
	(return (outline "550 ~A: Permission denied." file)))
    
    (outline "213-status of ~A:" file)
    (with-external-command (stream 
			    (concatenate 'vector 
			      #.(vector "/bin/ls" "/bin/ls" "-la")
			      (vector file)))
      (let (line)
	(while (setf line (read-line stream nil nil))
	       (outline "~A" line))))
    (outline "213 End of Status")))
  

;; XXX -- need errno for good error message
(defun cmd-dele (client file)
  (block nil
    (let ((fullpath (make-full-path (pwd client) file)))

      (if (and (restricted client) (out-of-bounds-p client fullpath))
	  (return (outline "550 ~A: Permission denied.")))
      
      (if (not (probe-file fullpath))
	  (return (outline "550 ~A: No such file or directory." file)))
      
      (if (and (anonymous client) *anonymous-delete-disabled*)
	  (return (outline "553 Delete permission denied.")))
      
      (if (not (ignore-errors (delete-file fullpath)))
	  (return (outline "550 ~A: Operation failed." file)))
      
      (outline "250 DELE command successful."))))

;; XXX -- need errno for good error message
(defun cmd-rmd (client file)
  (block nil
    (let ((fullpath (make-full-path (pwd client) file)))

      (if (and (restricted client) (out-of-bounds-p client fullpath))
	  (return (outline "550 ~A: Permission denied.")))
      
      (if (not (probe-file fullpath))
	  (return (outline "550 ~A: No such file or directory." file)))
      
      (if (and (anonymous client) *anonymous-rmdir-disabled*)
	  (return (outline "553 RMD Permission denied.")))
      
      (if (not (ignore-errors (delete-directory fullpath)))
	  (return (outline "550 ~A: Operation failed." file)))
      
      (outline "250 RMD command successful."))))
  
;; XXX -may want to use the 'mode' optional arg to make-directory
(defun cmd-mkd (client newdir)
  (block nil
    (let ((fullpath (make-full-path (pwd client) newdir)))
      
      (if (and (restricted client) (out-of-bounds-p client fullpath))
	  (return (outline "550 ~A: Permission denied.")))
      
      (if (and (anonymous client) *anonymous-mkdir-disabled*)
	  (return (outline "553 MKD Permission denied.")))
      
      (handler-case (make-directory fullpath)
	(file-error (c)
	  (return 
	    (outline "550 ~A: ~A." newdir 
		     (strerror (excl::file-error-errno c))))))
      
      (outline "257 ~S new directory created." fullpath))))
	       

;;; XXX --- doesn't have help for individual commands.
(defun cmd-help (client cmdtail)
  (block nil
    (if (string= cmdtail "")
	(return (help-main)))
    (let* ((spacepos (position #\space cmdtail))
	   (helpon (if spacepos 
		       (subseq cmdtail 0 spacepos)
		     cmdtail)))
      (if (equalp helpon "SITE")
	  (return (help-site client cmdtail)))
      (outline "550 Individual command HELP not implemented."))))

(defun help-main ()
  (outline "214-The following commands are recognized (* =>'s unimplemented).")
  (let ((i 0))
    (maphash 
     #'(lambda (key value)
	 (format *outlinestream* "   ~A~A~A"
		 (string-upcase key)
		 (if (not (cmd-implemented value)) "*" " ")
		 (if (= (length key) 3) " " ""))
	 (incf i)
	 (if (= i 8)
	     (progn
	       (outline "")
	       (setf i 0))))
     *cmds*)
    (if (not (= 0 i))
	(outline ""))
    (outline "214 Enjoy.")))



(defun cmd-mdtm (client file)
  (block nil
    (let ((fullpath (make-full-path (pwd client) file)))
      
      (if (and (restricted client) (out-of-bounds-p client fullpath))
	  (return (outline "550 ~A: Permission denied.")))
      
      (if (not (probe-file fullpath))
	  (return (outline "550 ~A: No such file or directory." file)))
      
      (if (not (eq :file (excl::filesys-type file)))
	  (return (outline "550 ~A: not a plain file." file)))
      
      (outline "213 ~A" 
	       (make-mdtm-string (file-write-date fullpath))))))

;; YYYYMMDDhhmmss   (in GMT)
(defun make-mdtm-string (utime)
  (locale-print-time 
   (+ utime (encode-universal-time 0 0 0 1 1 1900))
   :fmt "%Y%m%d%H%M%S" :stream nil))


(defun parse-cmdline (cmdline)
  (let ((args (delimited-string-to-list cmdline " "))
	switches
	comp
	patterns)
    (loop
      (if (= (length args) 0)
	  (return))
      (setf comp (pop args))
      (if (string= comp "--")
	  (progn
	    (push comp switches)
	    (return)))
      (if (match-regexp "^-" comp)
	  (push comp switches)
	(push comp patterns)))
    (setf patterns (append patterns args))
    (values (reverse switches) (reverse patterns))))

(defun glob (cmdline pwd)
  (if (string= cmdline "")
      (vector)
    (multiple-value-bind (switches patterns) (parse-cmdline cmdline)
      (let ((res (vector)))
	(dolist (patt patterns)
	  (setf res (concatenate 'vector res (glob-single patt pwd))))
	(concatenate 'vector (coerce switches 'vector) res)))))
	
(defun has-wildcard-p (string)
  (or (position #\* string)
      (position #\? string)
      (position #\[ string)))

(defun glob-single (patt pwd)
  (let ((bigpatt (make-full-path pwd patt)))
    (if (not (has-wildcard-p patt))
	(vector patt)
      (let ((matches (directory bigpatt)))
	(if (null matches)
	    (vector patt)
	  (mapcar #'enough-namestring matches))))))

(defun cmd-size (client file)
  (block nil
    (let ((fullpath (make-full-path (pwd client) file)))
      
      (if (and (restricted client) (out-of-bounds-p client fullpath))
	  (return (outline "550 ~A: Permission denied." file)))
      
      (if (not (probe-file fullpath))
	  (return (outline "550 ~A: No such file or directory." file)))

      (if (not (eq :file (excl::filesys-type fullpath)))
	  (return (outline "550 ~A: not a plain file." file)))
      
      (outline "213 ~D" (file-length fullpath)))))

(defun cmd-rnfr (client from)
  (block nil
    (let ((fullpath (make-full-path (pwd client) from)))
      
      (if (and (restricted client) (out-of-bounds-p client fullpath))
	  (return (outline "550 ~A: Permission denied.")))
      
      (if (not (probe-file fullpath))
	  (return (outline "550 ~A: No such file or directory." from)))
      
      (setf (rename-from client) from)
      (outline "350 File exists, ready for destination name"))))

;; Does the actual work.
;; XXX -- need errno info for proper error message.
(defun cmd-rnto (client to)
  (block nil
    (let ((fullpath (make-full-path (pwd client) to)))
      
      (if (null (rename-from client))
	  (return (outline "503 Bad sequence of commands.")))
      
      (if (and (anonymous client) *anonymous-rename-disabled*)
	  (return (outline "553 Rename permission denied.")))
      
      (if (and (restricted client) (out-of-bounds-p client fullpath))
	  (return (outline "550 ~A: Permission denied.")))
      
      (if (not (= 0 (rename (rename-from client) to)))
	  (outline "550 rename: Operation failed.")
	(outline "250 RNTO command successful."))
      
      (setf (rename-from client) nil))))

(defun cmd-site (client cmdtail)
  (block nil
    (let* ((spacepos (position #\space cmdtail))
	   (sitecmd (if spacepos (subseq cmdtail 0 spacepos) cmdtail))
	   (handler (cdr (assoc sitecmd *sitecmds* :test #'equalp))))
      (if (null handler)
	  (return (outline "550 'SITE ~A': command not understood." cmdtail)))
      (funcall handler client
	       (if spacepos
		   (subseq cmdtail (1+ spacepos))
		 "")))))

(defun site-chmod (client cmdtail)
  (block nil
    (let* ((spacepos (position #\space cmdtail))
	   (mode (if spacepos (subseq cmdtail 0 spacepos)))
	   (file (if spacepos (subseq cmdtail (1+ spacepos))))
	   (fullpath (make-full-path (pwd client) file)))
      (if (null spacepos)
	  (return
	    (outline "500 'SITE CHMOD ~A': Command not understood."
		     cmdtail)))
      
      (if (and (restricted client) (out-of-bounds-p client fullpath))
	  (return (outline "550 ~A: Permission denied.")))
      
      (if (not (probe-file fullpath))
	  (return
	    (outline "550 ~A: No such file or directory." file)))
      
      (if (and (anonymous client) *anonymous-chmod-disabled*)
	  (return (outline "553 Chmod permission denied.")))
      
      (setf mode (ignore-errors (parse-integer mode :radix 8)))
      
      (if (or (null mode) (< mode 0) (> mode #o777))
	  (return
	    (outline "501 CHMOD: Mode value must be between 0 and 0777")))
      
      (if (not (= 0 (chmod file mode)))
	  (return
	    (outline "550 ~A: Operation failed." file)))
      
      (outline "200 CHMOD command successful."))))

(defun site-umask (client umask)
  (block nil
    (let ((newumask (ignore-errors (parse-integer umask :radix 8))))
      (if (null newumask)
	  (return 
	    (outline "500 'SITE UMASK ~A': command not understood." umask)))
      (if (or (< newumask 0) (> newumask #o777))
	  (return 
	    (outline "501 Bad UMASK value")))
      (outline "200 UMASK set to 0~o (was 0~o)" newumask (client-umask client))
      (umask newumask)
      (setf (client-umask client) newumask))))

;; doesn't use cmdtail
(defun help-site (client cmdtail)
  (declare (ignore client cmdtail))
  (outline "214-The following SITE commands are recognized.")
  (dolist (ent *sitecmds*)
    (format *outlinestream* "   ~A" (string-upcase (car ent))))
  (outline "")
  (outline "214 Enjoy."))

;;;  Logging

(defun ctime (time &key strip-newline)
  (let ((ptime (ff:allocate-fobject :unsigned-int :foreign-static-gc)))
    (setf (ff:fslot-value ptime) time)
    (let ((res (without-interrupts (native-to-string (unix-ctime ptime)))))
      (if strip-newline
	  (subseq res 0 (1- (length res)))
	res))))

(defun ftp-log (&rest args)
  (util.posix-lock:with-stream-lock (*logstream*)
    (file-position *logstream* :end)
    (format *logstream* "~A [~D]: ~?"
	    (ctime (unix-time 0) :strip-newline t)
	    (getpid)
	    (first args)
	    (rest args))
    (force-output *logstream*)))


(defun open-logs ()
  (setf *logstream*
    (if *debug*
	*standard-output*
      (open *logfile*
	    :direction :output
	    :if-does-not-exist :create
	    :if-exists :append)))
  (setf *xferlogstream*
    (if *debug*
	*standard-output*
      (open *xferlog*
	    :direction :output
	    :if-does-not-exist :create
	    :if-exists :append))))
  
(defun close-logs ()
  (if (not *debug*)
      (progn
	(close *logstream*)
	(close *xferlogstream*))))

(defun xfer-log (client fullpath direction bytes)
  (util.posix-lock:with-stream-lock (*xferlogstream*)
    (file-position *xferlogstream* :end)
    (format *xferlogstream* 
	    "(~A ~A ~S ~S ~D ~S) ;; ~A ~A ~%"
	    (get-universal-time)
	    (socket:remote-host (client-sock client))
	    fullpath
	    direction
	    bytes
	    (if (anonymous client)
		(anonymous client)
	      (user client))
	    (socket:ipaddr-to-dotted (socket:remote-host (client-sock client)))
	    (ctime (unix-time 0) :strip-newline t))
    (force-output *xferlogstream*)))
  
;;;;;;;;;
(defun main (&rest args)
  (block nil
    #-(version>= 6 1)
    (error "aFTPd only works on ACL 6.1 or later.")

    (let ((configfile (get-opt "-f" args :param t)))
      (if configfile
	  (progn
	    (setf *configfile* configfile)
	    (if (not (probe-file *configfile*))
		(error "Config file ~A does not exist." *configfile*)))))
    
    (if (probe-file *configfile*)
	(load *configfile*))
    
    (if (get-opt "-d" args)
	(setf *debug* t))
    
    (let ((ftpport (get-opt "-p" args :param t :numeric t)))
      (if ftpport
	  (setf *ftpport* ftpport)))
    
    (if (not *debug*)
	(let ((pid (fork)))
	  (cond
	   ((< pid 0)
	    (error "Ack!! fork failed!"))
	   (( = pid 0)
	    ;; child
	    (ftp-chdir "/")
	    (disassociate))
	    (t
	     ;; parent
	     (return 0)))))
      (standalone-main)))

(defun get-opt (switch args &key param numeric)
  (block nil
    (let* ((switchpos (position switch args :test #'string=))
	   (argslen (length args))
	   (maxpos (1- argslen)))
      (if (null switchpos)
	  (return nil))
      (if (null param)
	  (return t))
      (if (= switchpos maxpos)
	  (usage))
      (let ((res (nth (1+ switchpos) args)))
	(if (null numeric)
	    (return res))
	(setf res (ignore-errors (parse-integer res)))
	(if (null res)
	    (usage))
	res))))

(defun usage ()
  (format t "Usage: aftpd [-f config_file_path] [-p port] [-d]~%")
  (format t "  Use -f to specify an alternate config file (default ~A).~%"
	  *configfile*)
  (format t "  Use -p to specify an alternate FTP port.~%")
  (format t "  Use -d to start aftpd in debug mode.~%")
  (format t "~%Note: -p and -f override any setting in the config file.~%~%")
  (exit t :quiet t))

#+linux
(defconstant TIOCNOTTY #x00005422)
#+solaris2 
(defconstant TIOCNOTTY #x00007471)

(defconstant O_RDWR #x00000002) ;; Linux and Solaris

#-(or linux solaris2)
(error "Platform not supported.")


(defmacro with-unix-open ((fd path flags) &body body)
  `(let ((,fd (unix-open ,path ,flags 0)))
     (unwind-protect (progn ,@body)
       (if (>= ,fd 0)
	   (unix-close ,fd)))))

;; I believe this will work w/ both SYSV and BSD (as long as the
;; constants are correct)
(defun disassociate ()
  (set-process-group)
  (with-unix-open (fd "/dev/tty" O_RDWR)
   (if (>= fd 0)
       (ioctl fd TIOCNOTTY 0)))
  (dotimes (i 3)
    (unix-close i)
    (if (not (= i (unix-open "/dev/null" O_RDWR 0)))
	(error "Got unexpected fd"))))

;;; setpgrp always succeeds in solaris.
(defun set-process-group ()
  #+solaris2
  (setpgrp)
  #+linux
  (if (not (= 0 (setpgrp)))
      (error "Failed to setpgrp"))
  )
  
  
;;;;;;;;;

(defun build ()
  (let (files)
    (dolist (file *extra-files*)
      (push (concatenate 'string file ".fasl") files))
    (setf files (cons "ftpd.fasl" (reverse files)))
    (setf files (append files '(:srecord :locale))) ;; add modules here
    (compile-file-if-needed "ftpd.cl")
    (generate-executable 
     "aftpd" 
     files)))
