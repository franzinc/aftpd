(in-package :user)

;; Linux 32-bit stat: Should be 88 bytes
(ff:def-foreign-type statbuf
    (:struct
     (st_dev1 :unsigned-int)
     (st_dev2 :unsigned-int)
     (pad1 :unsigned-short)
     (st_ino :unsigned-int)
     (st_mode :unsigned-int)
     (st_nlink :unsigned-int)
     (st_uid :unsigned-int)
     (st_gid :unsigned-int)
     (st_rdev1 :unsigned-int)
     (st_rdev2 :unsigned-int)
     (pad2 :unsigned-short)
     (st_size :unsigned-int)
     (st_blksize :unsigned-int)
     (st_blocks :unsigned-int)
     (st_atime :unsigned-int)
     (unused1 :unsigned-int)
     (st_mtime :unsigned-int)
     (unused2 :unsigned-int)
     (st_ctime :unsigned-int)
     (unused3 :unsigned-int)
     (unused4 :unsigned-int)
     (unused5 :unsigned-int)))

(defconstant S_IFMT	#o0170000) ;;	/* These bits determine file type.  */

;; /* File types.  */
(defconstant S_IFDIR	#o0040000) ;;	/* Directory.  */
(defconstant S_IFCHR	#o0020000) ;;	/* Character device.  */
(defconstant S_IFBLK	#o0060000) ;;	/* Block device.  */
(defconstant S_IFREG	#o0100000) ;;	/* Regular file.  */
(defconstant S_IFIFO	#o0010000) ;;	/* FIFO.  */
(defconstant S_IFLNK	#o0120000) ;;	/* Symbolic link.  */
(defconstant S_IFSOCK	#o0140000) ;;	/* Socket.  */

;; /* Protection bits.  */

(defconstant S_ISUID	#o04000) ;;	/* Set user ID on execution.  */
(defconstant S_ISGID	#o02000) ;;	/* Set group ID on execution.  */
(defconstant S_ISVTX	#o01000) ;;	/* Save swapped text after use (sticky).  */
(defconstant S_IREAD	#o0400) ;;	/* Read by owner.  */
(defconstant S_IWRITE	#o0200) ;;	/* Write by owner.  */
(defconstant S_IEXEC	#o0100) ;;	/* Execute by owner.  */

(defstruct stat
  dev
  ino
  mode
  nlink
  uid
  gid
  rdev
  size
  blksize
  blocks
  atime
  mtime
  ctime)
  
(ff:def-foreign-call (unix-stat "stat") () :strings-convert t
		     :returning :int)


;; XXX -- needs to collect errno info
(defun stat (path)
  (let ((sb (ff:allocate-fobject 'statbuf :foreign-static-gc)))
    (macrolet ((sbslot(slot) `(ff:fslot-value sb ,slot)))
      (if (not (= 0 (unix-stat path sb)))
	  (error "stat ~A failed" path))
      (make-stat
       :dev (logior (sbslot 'st_dev1)
		    (ash (sbslot 'st_dev2) 32))
       :ino (sbslot 'st_ino)
       :mode (sbslot 'st_mode)
       :nlink (sbslot 'st_nlink)
       :uid (sbslot 'st_uid)
       :gid (sbslot 'st_gid)
       :rdev (logior (sbslot 'st_rdev1)
		    (ash (sbslot 'st_rdev2) 32))
       :size (sbslot 'st_size)
       :blksize (sbslot 'st_blksize)
       :blocks (sbslot 'st_blocks)
       :atime (sbslot 'st_atime)
       :mtime (sbslot 'st_mtime)
       :ctime (sbslot 'st_ctime)))))

(defmacro S_ISREG(mode)
  `(not (= 0 (logand S_IFMT S_IFREG ,mode))))
