;; $Id: passwd.cl,v 1.1 2001/12/19 19:36:15 dancy Exp $

(defpackage :util.passwd
  (:use :common-lisp :excl)
  (:export
   #:pwent-name
   #:pwent-passwd
   #:pwent-uid
   #:pwent-gid
   #:pwent-gecos
   #:pwent-shell
   #:pwent-dir
   #:grent-name
   #:grent-passwd
   #:grent-gid
   #:grent-members
   #:spent-name
   #:spent-passwd
   #:spent-last-change
   #:spent-min
   #:spent-max
   #:spent-warn
   #:spent-inact
   #:spent-expire
   #:spent-flag
   #:get-pwent-by-name
   #:get-grent-by-name
   #:get-spent-by-name))
   
(in-package :util.passwd)

#-(or linux solaris2)
(error "Only Linux or Solaris supported.")

(ff:def-foreign-type passwd
    (:struct
     (pw_name (* :char))
     (pw_passwd (* :char))
     (pw_uid :int)
     (pw_gid :int)
     #+solaris2
     (pw_age (* :char))
     #+solaris2
     (pw_comment (* :char))
     (pw_gecos (* :char))
     (pw_dir (* :char))
     (pw_shell (* :char))))

(ff:def-foreign-call getpwnam () :strings-convert t)

(defstruct pwent
  name
  passwd
  uid
  gid
  gecos
  dir
  shell)


(ff:def-foreign-type group
    (:struct
     (gr_name (* :char))
     (gr_passwd (* :char))
     (gr_gid :int)
     (gr_mem (* (* :char)))))

(ff:def-foreign-call getgrnam () :strings-convert t)

(defstruct grent
  name
  passwd
  gid
  members)

(ff:def-foreign-call getspnam () :strings-convert t)

(ff:def-foreign-type spwd 
    (:struct
     (sp_namp (* :char))
     (sp_pwdp (* :char))
     (sp_lstchg :unsigned-int)
     (sp_min :int)
     (sp_max :int)
     (sp_warn :int)
     (sp_inact :int)
     (sp_expire :int)
     (sp_flag :unsigned-int)))

(defstruct spent
  name
  passwd
  last-change
  min
  max
  warn
  inact
  expire
  flag)
  

(defun get-pwent-by-name (name)
  (without-interrupts 
    (let ((pw (getpwnam name)))
      (if (= 0 pw)
	  nil
	(macrolet ((pwslot (slot) `(ff:fslot-value-typed 'passwd :c pw ,slot)))
	  (make-pwent
	   :name (native-to-string (pwslot 'pw_name))
	   :passwd (native-to-string (pwslot 'pw_passwd))
	   :uid (pwslot 'pw_uid)
	   :gid (pwslot 'pw_gid)
	   :gecos (native-to-string (pwslot 'pw_gecos))
	   :dir (native-to-string (pwslot 'pw_dir))
	   :shell (native-to-string (pwslot 'pw_shell))))))))

(defun get-grent-by-name (name)
  (without-interrupts 
    (let ((gr (getgrnam name)))
      (if (= 0 gr)
	  nil
	(macrolet ((grslot (slot) `(ff:fslot-value-typed 'group :c gr ,slot)))
	  (make-grent
	   :name (native-to-string (grslot 'gr_name))
	   :passwd (native-to-string (grslot 'gr_passwd))
	   :gid (grslot 'gr_gid)
	   :members (string-array-to-list (grslot 'gr_mem))))))))

(defun string-array-to-list (addr)
  (let (res ptr)
    (while (not (= 0 (setf ptr (ff:fslot-value-typed '(* :char) :c addr))))
	   (push (native-to-string ptr) res)
	   (incf addr #.(ff:sizeof-fobject '(* :char))))
    (reverse res)))

(defun get-spent-by-name (name)
  (without-interrupts
    (let ((sp (getspnam name)))
      (if (= 0 sp)
	  nil
	(macrolet ((spslot (slot) `(ff:fslot-value-typed 'spwd :c sp ,slot)))
	  (make-spent
	   :name (native-to-string (spslot 'sp_namp))
	   :passwd (native-to-string (spslot 'sp_pwdp))
	   :last-change (spslot 'sp_lstchg)
	   :min (spslot 'sp_min)
	   :max (spslot 'sp_max)
	   :warn (spslot 'sp_warn)
	   :inact (spslot 'sp_inact)
	   :expire (spslot 'sp_expire)
	   :flag (spslot 'sp_flag)))))))
