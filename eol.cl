;; Code stolen from Charley Cox.

(in-package :excl)

(eval-when (compile load eval)
  (export 'find-composed-external-format)
  (require :efmacs)
  (require :iodefs))

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

(defun fill-ef-templates (ef)
  (let ((file (generate-filled-ef-templates
	       :external-formats ef
	       :directory (sys:temporary-directory))))
    (load file)
    (delete-file file)))

(defun encapsulating-composer-p (ef)
  (declare (ignorable ef))
  #+(version>= 6 1) (ef-composing-functions (find-external-format ef))
  #-(version>= 6 1) nil)


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

(defun runtime-ef-p (ef)
  (or (not (ef-char-to-octets-macro ef))
      (not (ef-octets-to-char-macro ef))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def-external-format :cr)

(def-char-to-octets-macro :cr (char
			       state
			       &key put-next-octet external-format)
  (declare (ignorable state))
  (let ((char-var (gensym)))
    `(let ((,char-var ,char))
       (char-to-octets ,external-format
		       (if* (eq #\newline ,char-var)
			  then #\return
			  else ,char-var)
		       ,state
		       :put-next-octet ,put-next-octet))))

(def-octets-to-char-macro :cr (state
			       &key get-next-octet external-format
			       octets-count-loc unget-octets)
  (let ((char-var (gensym)))
    `(let ((,char-var (octets-to-char ,external-format ,state
				      :octets-count-loc ,octets-count-loc
				      :unget-octets ,unget-octets
				      :get-next-octet ,get-next-octet
				      :oc-eof-macro nil)))
       (if* (eq #\return ,char-var)
	  then #\newline
	  else ,char-var))))

(defpackage :eol
  (:use :common-lisp :excl)
  (:export :eol-convention)
  (:shadow :eol-convention))

(in-package :eol)

;; This function assumes the eol composer is the outer-most composer.
(defun eol-convention (stream &aux (ef (find-external-format
					(stream-external-format stream))))
  (if* (composed-external-format-p ef)
     then (let ((composer (ef-composer-ef ef)))
	    (if* (or #+(version>= 6 1) (eq composer
					   (find-external-format :e-crlf))
		     (eq composer (find-external-format :crlf))
		     (eq composer (find-external-format :crcrlf))
		     #+(version>= 6 1) (eq composer
					   (find-external-format :e-crcrlf)))
	       then (values :dos (ef-composee-ef ef))
	     elseif (eq composer (find-external-format :cr))
	       then (values :mac (ef-composee-ef ef))
	       else (values :unix ef)))
     else (values :unix ef)))

(defun (setf eol-convention) (convention stream)
  (multiple-value-bind (cur base-ef) (eol-convention stream)
    (declare (ignore cur))
    (setf (stream-external-format stream)
      (ecase convention
	(:unix base-ef)
	(:dos (find-composed-external-format
	       #+(version>= 6 1) ':e-crlf
	       #-(version>= 6 1) ':crlf
	       base-ef))
	(:mac (find-composed-external-format :cr base-ef)))))
  ;; return value
  (eol-convention stream))
