;; $Id: ftpd.cl,v 1.2 2001/12/06 18:18:35 dancy Exp $

(in-package :user)

(eval-when (compile)
  (proclaim '(optimize (safety 1) (space 1) (speed 3) (debug 2))))
  
;; Need an external configuration file.
(defparameter *ftpport* 21)
;; Control channel timeout
(defparameter *idletimeout* 120)
;; The maximum number of seconds between writes to the data socket
(defparameter *transfertimeout* 120)
;; Maximum time to wait for PASV or PORT connections to complete.
(defparameter *connecttimeout* 60)
(defparameter *badpwdelay* 5)
(defparameter *max-password-attempts* 2)
(defparameter *pasvrange* '(51000 . 51999))
(defparameter *interface* nil) ;; nil means all
(defparameter *default-umask* #o022) 
(defparameter *anonymous-ftp-names* '("ftp" "anonymous"))
(defparameter *anonymous-ftp-account* "ftp")
(defparameter *welcome-msg-file* "welcome.msg")
(defparameter *message-file* ".message")
(defparameter *quarantine-anonymous-uploads* t)
(defparameter *anonymous-rename-restricted* t)
(defparameter *anonymous-mkdir-restricted* t)
(defparameter *anonymous-rmdir-restricted* t)
(defparameter *anonymous-delete-restricted* t)
(defparameter *anonymous-chmod-restricted* t)

(defparameter *debug* t)

;; Put longest extensions first
(defparameter *conversions*
    '((".tar.bz2" . "/bin/tar cjf - ~A")
      (".tar.gz" . "/bin/tar czf - ~A")
      (".tar.Z" . "/bin/tar cZf - ~A")
      (".tar" . "/bin/tar cf - ~A")
      (".zip" . "/bin/zip -qq -r - ~A")
      (".bz2" . "/bin/bzip2 -c ~A")
      (".gz" . "/bin/gzip -9 -c ~A")
      (".Z" . "/bin/compress -c ~A")))
      

(ff:def-foreign-call fork () :strings-convert nil :returning :int)
(ff:def-foreign-call wait () :strings-convert nil :returning :int)
(ff:def-foreign-call waitpid () :strings-convert nil :returning :int)
(ff:def-foreign-call (unix-crypt "crypt") () :strings-convert t 
		     :returning :unsigned-int)
(ff:def-foreign-call setgid () :strings-convert nil :returning :int)
(ff:def-foreign-call setuid () :strings-convert nil :returning :int)
(ff:def-foreign-call getuid () :strings-convert nil :returning :int)
(ff:def-foreign-call getgid () :strings-convert nil :returning :int)
(ff:def-foreign-call geteuid () :strings-convert nil :returning :int)
(ff:def-foreign-call getegid () :strings-convert nil :returning :int)
(ff:def-foreign-call initgroups () :strings-convert t :returning :int)
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


(eval-when (compile)
  (compile-file-if-needed "getpwnam.cl")
  (compile-file-if-needed "stat.cl")
  (compile-file-if-needed "eol.cl"))

(eval-when (compile load eval)
  (load "getpwnam.fasl")
  (load "stat.fasl")
  (load "eol.fasl")
  (require :acldns))

;; System dependent.
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

(defun standalone-main ()
  (let ((serv (socket:make-socket :connect :passive 
				  :local-host *interface*
				  :local-port *ftpport*
				  :reuse-address t)))
    (socket:configure-dns :auto t)
    (unwind-protect
	(loop
	  (let ((client (ignore-errors (socket:accept-connection serv))))
	    (if client
		(progn
		  (format t "Connection made from ~A.~%"
			  (socket:ipaddr-to-dotted 
			   (socket:remote-host client)))
		  (spawn-client client serv)))))
      ;; cleanup forms
      (format t "Cleanup: Closing server socket.~%")
      (close serv))))

;; Orphans the child so that 'init' will pick it up.
(defun spawn-client (sock serv)
  (let ((pid (fork)))
    (if (= pid 0)
	(let ((pid (fork)))
	  (if (= pid 0)
	      (progn
		(close serv) ;; don't need it
		(if *debug*
		    (ftpd-main sock)
		  (handler-case (ftpd-main sock)
		    (t (c)
		      (format t "Error ~S~%" c))))
		(exit t :no-unwind t :quiet t)) ;; make sure this lisp exits.
	    (exit t :no-unwind t :quiet t))) ;; orphan the child
      (progn
	(close sock) ;; we don't need it
	(waitpid pid 0 0))))) ;; should happen quickly.

;;; C library utils

(defun strerror (errno)
  (without-interrupts
    (native-to-string (unix-strerror errno))))

(defun crypt (string salt)
  (without-interrupts
   (native-to-string (unix-crypt string salt))))

(defun ctime (time &key strip-newline)
  (let ((ptime (ff:allocate-fobject :unsigned-int :foreign-static-gc)))
    (setf (ff:fslot-value ptime) time)
    (let ((res (without-interrupts (native-to-string (unix-ctime ptime)))))
      (if strip-newline
	  (subseq res 0 (1- (length res)))
	res))))

;;;


(defparameter *outlinestream* 'outlinestream-not-bound)

;; never call outline w/ a first argument that is anything
;; but a format string.
(defmacro outline (&rest args)
  `(progn 
     (funcall #'format *outlinestream* ,@args)
     (write-char #\return *outlinestream*)
     (write-char #\newline *outlinestream*)
     (force-output *outlinestream*)))

(defmacro with-output-to-client ((client) &body body)
  `(let ((*outlinestream* (client-sock ,client)))
     ,@body))

;;; 

(defun spawn-command (cmdvec)
  (multiple-value-bind (stdout stderr pid)
      (run-shell-command cmdvec
			 :input "/dev/null"
			 :output :stream
			 :error-output :stream
			 :wait nil)
    (mp:process-run-function "stderr reader" 'stderr-reader stderr)
    (values stdout pid)))

(defun stderr-reader (stderr)
  (let (line)
    (while (setf line (read-line stderr nil nil))
	   (write-line line)
	   (force-output)))
  (close stderr))

(defmacro with-external-command ((streamvar cmdvec) &body body)
  (let ((pidvar (gensym)))
    `(multiple-value-bind (,streamvar ,pidvar) (spawn-command ,cmdvec)
       (unwind-protect (progn ,@body)
	 (close ,streamvar)
	 (sys:reap-os-subprocess :pid ,pidvar)))))

;;;


(defun get-request (client)
  (let ((sock (client-sock client))
	(buffer (make-string 1024))
	(pos 0)
	char)
    (mp:with-timeout (*idletimeout* :timeout)
      (loop
	;; Treat long lines at multiple lines of input
	(if (= pos 1024)
	    (return (subseq buffer 0 pos)))
	(setf char 
	  (handler-case (read-char sock)
	    (t ()
	      nil)))
	(if (null char)
	    (return :eof))
	(if (char= char #\newline)
	    (if (and (> pos 0) (char= (schar buffer (1- pos)) #\return))
		(return (subseq buffer 0 (1- pos)))))
	(setf (schar buffer pos) char)
	(incf pos)))))


(defun ftpd-main (sock)
  (unwind-protect
      (let ((client (make-instance 'client :sock sock))
	    (*locale* (find-locale :c))) 
	(umask (client-umask client))
	(with-output-to-client (client)
	  (outline "220 Welcome to Allegro FTPd")
	  (loop
	    (let ((req (get-request client)))
	      (if (eq req :eof)
		  (return (cleanup client)))
	      (if (eq req :timeout)
		  (progn
		    (outline
		     "421 Timeout: closing control connection.")
		    (return (cleanup client))))
	      (if (eq (dispatch-cmd client req) :quit)
		  (return (cleanup client)))))))
    (ignore-errors (close sock))))

(defun dispatch-cmd (client cmdstring)
  (block nil
    (let ((spacepos (position #\space cmdstring))
	  cmdname
	  entry)
      (if (null spacepos)
	  (setf cmdname cmdstring)
	(setf cmdname (subseq cmdstring 0 spacepos)))
      
      (if (equalp cmdname "pass")
	  (format t "~A: PASS XXXXXX~%"
		  (socket:ipaddr-to-dotted 
		   (socket:remote-host (client-sock client))))
	(format t "~A: ~A~%"
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
  (format t "Client from ~A disconnected.~%"
	  (socket:ipaddr-to-dotted
	   (socket:remote-host (client-sock client))))
  (cleanup-data-connection client))

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
    
    (if (member user *anonymous-ftp-names* :test #'equalp)
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
      (format t "User ~A logged in.~%" (user client))
      (setf (pwd client) (pwent-dir pwent))

      (if (anonymous client)
	  (anonymous-setup client))
      
      ;; Set up
      (if (not (= 0 (setgid (pwent-gid pwent))))
	  (progn
	    (format t "Failed to setgid(~D)~%" (pwent-gid pwent))
	    (outline "421 Local configuration error.")
	    (return :quit)))
      (if (not (= 0 (initgroups (user client) (pwent-gid pwent))))
	  (progn
	    (format t "Failed to initgroups~%")
	    (outline "421 Local configuration error.")
	    (return :quit)))
      
      (if (not (= 0 (setuid (pwent-uid pwent))))
	  (progn
	    (format t "Failed to setuid(~D)~%" (pwent-uid pwent))
	    (outline "421 Local configuration error.")
	    (return :quit)))
      (if (null (ftp-chdir (pwent-dir pwent)))
	  (progn
	    (format t "Failed to chdir(~A)~%" (pwent-dir pwent))
	    
	    ;; Anonymous users have no alternative
	    (if (anonymous client)
		(progn
		  (outline "421 Local configuration error.")
		  (return :quit)))
	    
	    (if (not (ftp-chdir "/"))
		(progn
		  (format t "Failed to chdir(/)~%")
		  (outline "421 Local configuration error.")
		  (return :quit))
	      (progn
		(setf (pwent-dir pwent) "/")
		(outline "230-No directory! Logging in with home=/")))))

      (setf (logged-in client) t)
      (cleanup-data-connection client) 
      (dump-welcome-msg client)
      (outline "230 User ~A logged in." (user client)))))

(defun anonymous-setup (client)
  (block nil
    (let ((pwent (pwent client)))
      (if (null (ftp-chdir (pwent-dir pwent)))
	  (progn
	    (format t "Failed to chdir(~A)~%" (pwent-dir pwent))
	    (outline "421 Local configuration error.")
	    (return nil)))
      (if (not (= 0 (chroot (pwent-dir pwent))))
	  (progn
	    (format t "Failed to chroot(~A)~%" (pwent-dir pwent))
	    (outline "421 Local configuration error.")
	    (return nil)))
      (setf (pwent-dir pwent) "/")
      (setf (pwd client) "/")
      t)))

(defun dump-welcome-msg (client)
  (declare (ignore client))
  (block nil
    (if (or (null *welcome-msg-file*)
	    (null (probe-file *welcome-msg-file*)))
	(return))
    (with-open-file (f *welcome-msg-file*)
      (let (line)
	(while (setf line (read-line f nil nil))
	       (outline "230-~A" line))))))

(defun cmd-pwd (client cmdtail)
  (declare (ignore cmdtail))
  (outline "257 \"~A\" is current directory."
	   (pwd client)))

(defun cmd-noop (client cmdtail)
  (declare (ignore client cmdtail))
  (outline "200 NOOP command successful."))

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
		(format t "Client from ~A tried to set PORT ~A:~A~%"
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
      (outline "227 Entering Passive Mode (~D,~D,~D,~D,~D,~D) [~D]"
	       (logand (ash addr -24) #xff)
	       (logand (ash addr -16) #xff)
	       (logand (ash addr -8) #xff)
	       (logand addr #xff)
	       (logand (ash port -8) #xff)
	       (logand port #xff)
	       port))))

(defun cmd-type (client cmdtail)
  (block nil
    (let ((params (delimited-string-to-list cmdtail " ")))
      (cond
       ((equalp cmdtail "i")
	(setf (client-type client) :image)
	(outline "200 Type set to I."))
       ((equalp cmdtail "e")
	(outline "504 Type E not implemented."))
       ((equalp (first params) "a")
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

(defun data-connection-prepared-p (client)
  (or (dataport-addr client)
      (pasv client)))

;; Drops connections made by other hosts.
(defun accept-pasv-connection-from-client (client)
  (loop
    (let ((newsock (ignore-errors (socket:accept-connection (pasv client)))))
      (if newsock
	  (if (not (= (socket:remote-host newsock)
		      (socket:remote-host (client-sock client))))
	      (progn
		(format t "Non-client connection to PASV port ~A:~A made by ~A.~%"
			(socket:ipaddr-to-dotted 
			 (socket:local-host (client-sock client)))
			(socket:local-port (pasv client))
			(socket:ipaddr-to-dotted
			 (socket:remote-host newsock)))
		(ignore-errors (close newsock)))
	    (return newsock))))))
    
(defun establish-data-connection (client)
  (block nil
    (setf (dataport-sock client)
      (mp:with-timeout (*connecttimeout* :timeout)
	(if (pasv client)
	    (accept-pasv-connection-from-client client)
	  (ignore-errors 
	   (socket:make-socket :remote-host (dataport-addr client)
			       :remote-port (dataport-port client)
			       :local-host *interface*
			       :type :hiper)))))
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

(defmacro ftp-with-open-file ((streamsym errsym path &rest rest) &body body)
  `(let (,errsym)
     (let ((,streamsym 
	    (handler-case (open ,path ,@rest)
	      (file-error (c)
		(setf ,errsym (excl::file-error-errno c))
		nil))))
       (unwind-protect (progn ,@body)
	 (if ,streamsym
	     (close ,streamsym))))))

(defun cmd-retr (client file)
  (block nil
    (if (null (data-connection-prepared-p client))
	(return (outline "452 No data connection has been prepared.")))
    
    (let ((fullpath (make-full-path (pwd client) file)))
      (if (not (probe-file fullpath))
	  (multiple-value-bind (conv realname)
	      (conversion-match fullpath)
	    (if conv
		(return (start-conversion client conv realname)))
	    (return (outline "550 ~A: No such file or directory." file))))

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
       (let ((stat (ignore-errors (stat file))))
	 (if (null stat)
	     (return (outline "550 ~A: RETR failed." file)))
	 (if (not (S_ISREG (stat-mode stat)))
	     (return (outline "550 ~A: not a plain file." file)))
	 
	 (transmit-stream client f fullpath))))))
    
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

(defun start-conversion (client conversion file)
  (block nil
    (if (not (eq (client-type client) :image))
	(return 
	  (outline "550 This is a BINARY file, using ASCII mode to transfer will corrupt it.")))
    (if (not (= 0 (client-restart client)))
	(return
	  (outline "550 REST not allowed with conversions.")))
    (let* ((cmdstring (format nil conversion file))
	   (cmdlist (delimited-string-to-list cmdstring #\space))
	   (cmdvec (coerce (cons (first cmdlist) cmdlist) 'vector)))
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
	  (t (c)
	    (outline "426 Error: ~A" c)
	    nil))
	(outline "226 Transfer complete."))
    
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
	(extf (find-composed-external-format :crlf 
					     (crlf-base-ef :latin1)))
	got)
    (while (not (= 0 (setf got (read-sequence inbuffer f :partial-fill t))))
	   (multiple-value-bind (ignore count)
	       (string-to-octets inbuffer 
				 :null-terminate nil 
				 :mb-vector outbuffer
				 :end got
				 :external-format extf)
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
    (if (not (= 0 (client-restart client)))
	(return (outline "452 REST > 0 not supported with STOR.")))
    
    (if (null (data-connection-prepared-p client))
	(return (outline "452 No data connection has been prepared.")))
    
    (with-umask ((if (and (anonymous client) *quarantine-anonymous-uploads*)
		     #o777 (client-umask client)))
      (ftp-with-open-file 
       (f errno (make-full-path (pwd client) file)
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
	     (t (c)
	       (outline "426 Error: ~A" c)
	       nil))
	   (outline "226 Transfer complete."))

       (cleanup-data-connection client)))))
       


(defun store-file (client out)
  (if (eq (client-type client) :ascii-nonprint)
      (store-file-ascii client out)
    (store-file-binary client out))
  t)

(defun store-file-ascii (client out)
  (let ((in (dataport-sock client))
	lastchar
	char)
    (while (setf char (read-char in nil nil))
	   (if (and lastchar (char= lastchar #\return) (char= char #\newline))
	       (progn
		 (write-char #\newline out)
		 (setf lastchar nil))
	     (progn
	       (if lastchar
		   (write-char lastchar out))
	       (setf lastchar char))))
    (if lastchar
	(write-char lastchar out))))

(defun store-file-binary (client out)
  (let ((in (dataport-sock client))
	(buffer (make-array 65536 :element-type '(unsigned-byte 8)))
	got)
    (while (not (= 0 (read-vector buffer in)))
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
    (if (not (match-regexp #.(compile-regexp "^~") path))
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
  
(defun make-full-path (pwd path)
  (block nil
    (if (char= (schar path 0) #\/)
	(if (and (not (string= path "/"))
		 (char= (schar path (1- (length path))) #\/))
	    (return (subseq path 0 (1- (length path))))
	  (return path)))
    (let ((pwd (if (string= pwd "/") 
		   '("")
		 (reverse (delimited-string-to-list pwd #\/))))
	  (path (delimited-string-to-list path #\/)))
      (dolist (comp path)
	(cond
	 ((or (string= comp "") (string= comp "."))
	  ) ;; do nothing
	 ((string= comp "..")
	  (if (string= (pop pwd) "")
	      (setf pwd '(""))))
	 (t
	  (push comp pwd))))
      (if (equalp pwd '(""))
	  "/"
	(list-to-delimited-string (reverse pwd) #\/)))))

(defun cmd-list (client path)
  (block nil
    (if (null (data-connection-prepared-p client))
	(return (outline "452 No data connection has been prepared.")))
    
    (if (null (establish-data-connection client))
	(return))
    
    (outline "150 Opening ASCII mode data connection for /bin/ls.")

    (let ((*outlinestream* (dataport-sock client)))
      (with-external-command (stream 
			      (concatenate 'vector
				#.(vector "/bin/ls" "/bin/ls" "-la")
				(glob path (pwd client))))
	(let (line)
	  (while (setf line (read-line stream nil nil))
		 (outline "~A" line)))))
    
    (cleanup-data-connection client)
    (outline "226 Transfer complete.")))

(defun cmd-nlst (client path)
  (block nil
    (if (null (data-connection-prepared-p client))
	(return (outline "452 No data connection has been prepared.")))
    
    (if (null (establish-data-connection client))
	(return))
    
    (outline "150 Opening ASCII mode data connection for file list.")

    (let ((*outlinestream* (dataport-sock client)))
      (with-external-command (stream 
			      (vector "/bin/ls" "/bin/ls"
				      (if (not (string= path ""))
					  path
					(pwd client))))
	(let (line)
	  (while (setf line (read-line stream nil nil))
		 (outline "~A" line)))))
    
    (cleanup-data-connection client)
    (outline "226 Transfer complete.")))
    
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

(defun cmd-stat-file (client file)
  (block nil
    (outline "213-status of ~A:" file)
    (with-external-command (stream 
			    (concatenate 'vector 
			      #.(vector "/bin/ls" "/bin/ls" "-la")
			      (glob file (pwd client))))
      (let (line)
	(while (setf line (read-line stream nil nil))
	       (outline "~A" line))))
    (outline "213 End of Status")))
  

;; XXX -- need errno for good error message
(defun cmd-dele (client file)
  (block nil
    (let ((fullpath (make-full-path (pwd client) file)))
    
      (if (not (probe-file fullpath))
	  (return (outline "550 ~A: No such file or directory." file)))
      
      (if (and (anonymous client) *anonymous-delete-restricted*)
	  (return (outline "553 Delete permission denied.")))
      
      (if (not (ignore-errors (delete-file fullpath)))
	  (return (outline "550 ~A: Operation failed." file)))
      
      (outline "250 DELE command successful."))))

;; XXX -- need errno for good error message
(defun cmd-rmd (client file)
  (block nil
    (let ((fullpath (make-full-path (pwd client) file)))
      
      (if (not (probe-file fullpath))
	  (return (outline "550 ~A: No such file or directory." file)))
      
      (if (and (anonymous client) *anonymous-rmdir-restricted*)
	  (return (outline "553 RMD Permission denied.")))
      
      (if (not (ignore-errors (delete-directory fullpath)))
	  (return (outline "550 ~A: Operation failed." file)))
      
      (outline "250 RMD command successful."))))
  
;; XXX -may want to use the 'mode' optional arg to make-directory
(defun cmd-mkd (client newdir)
  (block nil
    (let ((fullpath (make-full-path (pwd client) newdir)))
      
      (if (and (anonymous client) *anonymous-mkdir-restricted*)
	  (return (outline "553 MKD Permission denied.")))
      
      (handler-case (make-directory fullpath)
	(file-error (c)
	  (return 
	    (outline "550 ~A: ~A." newdir 
		     (strerror (excl::file-error-errno c))))))
      
      (outline "257 ~S new directory created." fullpath))))
	       

;;; XXX -- doesn't use cmdtail
(defun cmd-help (client cmdtail)
  (declare (ignore cmdtail client))
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
    (let (stat)
      (if (not (probe-file (make-full-path (pwd client) file)))
	  (return (outline "550 ~A: No such file or directory." file)))
      
      (setf stat (ignore-errors (stat file)))
      
      (if (null stat)
	  (return (outline "550 ~A: Command failed." file)))
      
      (if (not (S_ISREG (stat-mode stat)))
	  (return (outline "550 ~A: not a plain file." file)))
      
      (outline "213 ~A" (make-mdtm-string (stat-mtime stat))))))

;; YYYYMMDDhhmmss
(defun make-mdtm-string (mtime)
  (let ((ptime (ff:allocate-fobject :unsigned-int :foreign-static-gc)))
    (setf (ff:fslot-value ptime) mtime)
    (without-interrupts
      (let ((tm (gmtime ptime))
	    (buffer (make-array 20 :element-type '(unsigned-byte 8) 
				:allocation :static-reclaimable)))
	(strftime buffer 20 "%Y%m%d%H%M%S" tm)
	(octets-to-string buffer)))))


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

;;; this isn't quite right.
(defun glob-single (patt pwd)
  (let ((bigpatt (make-full-path pwd patt)))
    (if (not (has-wildcard-p patt))
	(vector patt)
      (let ((matches (directory bigpatt)))
	(if (null matches)
	    (vector patt)
	  (mapcar #'(lambda(ent) (make-relative ent pwd)) matches))))))

(defun make-relative (path pwd)
  (if (pathnamep path)
      (setf path (namestring path)))
  (if (string= pwd "/")
      (subseq path 1)
    (if (string= (concatenate 'string pwd "/")
		 (subseq path 0 (1+ (length pwd))))
	(subseq path (1+ (length pwd)))
      path)))

(defun basename (path)
  (if (pathnamep path)
      (setf path (namestring path)))
  (let ((slashpos (position #\/ path :from-end t)))
    (if (null slashpos)
	path
      (subseq path (1+ slashpos)))))
    
(defun cmd-size (client file)
  (block nil
    (let (stat)
      
      (if (not (probe-file (make-full-path (pwd client) file)))
	  (return (outline "550 ~A: No such file or directory." file)))
      
      (setf stat (ignore-errors (stat file)))
      
      (if (null stat)
	  (return (outline "550 ~A: Command failed." file)))
      
      (if (not (S_ISREG (stat-mode stat)))
	  (return (outline "550 ~A: not a plain file." file)))
      
      (outline "213 ~D" (stat-size stat)))))

(defun cmd-rnfr (client from)
  (block nil

    (if (not (probe-file (make-full-path (pwd client) from)))
	(return (outline "550 ~A: No such file or directory." from)))
    
    (setf (rename-from client) from)
    (outline "350 File exists, ready for destination name")))

;; Does the actual work.
;; XXX -- need errno info for proper error message.
(defun cmd-rnto (client to)
  (block nil
    (if (null (rename-from client))
	(return (outline "503 Bad sequence of commands.")))
    
    (if (and (anonymous client) *anonymous-rename-restricted*)
	(return (outline "553 Rename permission denied.")))
    
    (if (not (= 0 (rename (rename-from client) to)))
	(outline "550 rename: Operation failed.")
      (outline "250 RNTO command successful."))
    
    (setf (rename-from client) nil)))

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
	   (file (if spacepos (subseq cmdtail (1+ spacepos)))))
      (if (null spacepos)
	  (return
	    (outline "500 'SITE CHMOD ~A': Command not understood."
		     cmdtail)))
      
      (if (not (probe-file (make-full-path (pwd client) file)))
	  (return
	    (outline "550 ~A: No such file or directory." file)))
      
      (if (and (anonymous client) *anonymous-chmod-restricted*)
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
