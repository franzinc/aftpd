;; This software is Copyright (c) Franz Inc., 2001-2002.
;; Franz Inc. grants you the rights to distribute
;; and use this software as governed by the terms
;; of the Lisp Lesser GNU Public License
;; (http://opensource.franz.com/preamble.html),
;; known as the LLGPL.
;;
;; $Id: posix-lock.cl,v 1.3 2002/09/16 21:31:24 layer Exp $

(defpackage :util.posix-lock
  (:use :excl :common-lisp)
  (:export 
   #:lock-stream 
   #:unlock-stream
   #:with-stream-lock))

(in-package :util.posix-lock)

;; Provided by jkf.

;; There are two kinds of locks flock and posix (fcntl,lockf).
;; They act independently so you have to choose the lock that you
;; expect others to use.
;; mail programs use posix locks, so we shall as well.
;; you can't get a lock on the fd unless the fd is open for read/write
;; or write-only.

;; mods by dancy to make it lock/unlock the entire file.

;; lockf is a fcntl wrapper function
(ff:def-foreign-call (lockf "lockf") ((fd :int)(cmd :int)(len :int))
  :returning :int)

(eval-when (compile load eval)
(defconstant F_ULOCK 0) ; unlock
(defconstant F_LOCK  1) ; exclusive lock
(defconstant F_TLOCK 2) ; test and lock
(defconstant F_TEST  3) ; test
) ;; eval-when


(defmacro with-saved-file-position ((stream) &body body)
  (let ((streamvar (gensym))
	(oldfileposvar (gensym)))
    `(let* ((,streamvar ,stream)
	    (,oldfileposvar (file-position ,streamvar)))
       (file-position ,streamvar 0)
       (unwind-protect
	   (progn
	     ,@body)
	 (file-position ,streamvar ,oldfileposvar)))))

(defun lock-stream (stream &key (wait nil))
  ;; try to lock the stream, return t if success
  (let ((code (if* wait
		 then F_LOCK
		 else F_TLOCK)))
    (let ((ans (with-saved-file-position (stream)
		 (lockf (io-handle stream) code 0))))
      (if* (< ans 0)
	 then nil
	 else t))))

(defun unlock-stream (stream)
  (with-saved-file-position (stream)
    (lockf (io-handle stream) F_ULOCK 0)))

(defun io-handle (stream)
  (or (excl::stream-input-handle stream) 
      (excl::stream-output-handle stream)))

(defmacro with-stream-lock ((stream) &body body)
  (let ((streamvar (gensym)))
    `(let ((,streamvar ,stream))
       (lock-stream ,streamvar :wait t)
       (unwind-protect
	   (progn
	     ,@body)
	 (unlock-stream ,streamvar)))))
