;; This software is Copyright (c) Franz Inc., 2001-2002.
;; Franz Inc. grants you the rights to distribute
;; and use this software as governed by the terms
;; of the Lisp Lesser GNU Public License
;; (http://opensource.franz.com/preamble.html),
;; known as the LLGPL.
;;
;; $Id: eol.cl,v 1.5 2002/09/23 22:58:56 layer Exp $
;;
;; This code is part of ACL 6.2.

#-(version>= 6 2)
(defpackage :excl (:export #:find-composed-external-format))

(in-package :excl)

(eval-when (compile load eval)
  (require :efmacs)
  (require :iodefs))

#-(version>= 6 2)
(defun find-composed-external-format (composer composee
				      &aux (composer (find-external-format
						      composer))
					   (composee (find-external-format
						      composee)))
  ;; First check to see if desired ef already exists.
  (dolist (ef (all-external-formats))
    (when (and (eq composer (ef-composer-ef ef))
	       (eq composee (ef-composee-ef ef)))
      (return-from find-composed-external-format ef)))

  ;; It's pretty simple if the composer is an encapsulator.
  (when (encapsulating-composer-p composer)
    (return-from find-composed-external-format
      (find-external-format `(,(ef-name composer) ,(ef-name composee)))))

  ;; The external-formats may already be in lisp and in runtime mode, which
  ;; means the macros needed for composition have been eliminated from this
  ;; lisp session.  We use the following to try loading the ef again to make
  ;; sure we have its macros.
  ;;
  ;; Remember if either ef is in runtime mode so that we can put it back that
  ;; way when we're done.
  (let ((composer-runtime (runtime-ef-p composer))
	(composee-runtime (runtime-ef-p composee)))
    (when composer-runtime
      (reload-ef composer))
    (when composee-runtime
      (reload-ef composee))

    ;; Now we are ready to compose the external-formats.  We work around the
    ;; fact that compose-external-formats is a macro.
    (let ((nef (funcall (compile nil `(lambda ()
					(compose-external-formats
					 ,(ef-name composer)
					 ,(ef-name composee)))))))
      ;; Now we have the new external-format (in nef).  Before returning,
      ;; though, let's pre-fill the templates.
      ;; This step is optional, but it suppresses notices that may come up
      ;; later while using this external-format.
      (fill-ef-templates nef)
    
      ;; Switch external-formats back to runtime mode.
      (when composer-runtime
	(switch-ef-to-runtime composer))
      (when composee-runtime
	(switch-ef-to-runtime composee))
      nef)))

#-(version>= 6 2)
(defun fill-ef-templates (ef)
  (let ((file (generate-filled-ef-templates
	       :external-formats ef
	       :directory (sys:temporary-directory))))
    (load file)
    (delete-file file)))

#-(version>= 6 2)
(defun encapsulating-composer-p (ef)
  (declare (ignorable ef))
  #+(version>= 6 1) (ef-composing-functions (find-external-format ef))
  #-(version>= 6 1) nil)


#-(version>= 6 2)
(defun reload-ef (ef)
  ;; This is a hack.
  (let ((*modules*
	 (remove-if #'(lambda (x)
			(eql 0 (search "ef-" x :test #'string-equal)))
		    *modules*)))
    (dolist (name (cons (ef-name ef) (ef-nicknames ef)))
      (when (ignore-errors
	     (require (concatenate 'string "ef-" (string-downcase
						  (string name)))))
	(return-from reload-ef)))
    ;; If we get this far (happens on Windows), then try removing "-base"
    ;; from name.
    (let* ((name (string (ef-name ef)))
	   (end (mismatch name "-base" :from-end t :test #'char-equal)))
      (ignore-errors
       (require (concatenate 'string "ef-" (string-downcase
					    (subseq name 0 end))))))))

#-(version>= 6 2)
(defun runtime-ef-p (ef)
  (or (not (ef-char-to-octets-macro ef))
      (not (ef-octets-to-char-macro ef))))
