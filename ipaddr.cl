(in-package :user)

(defstruct network-address
  network
  mask)

;; Acceptable formats:
;; a.b.c.d
;; a.b.c.d/x
;; a.b.c.d/x.y.z.w
(defun parse-addr (addr)
  (setf addr (string-trim '(#\space) addr))
  (let* ((slashpos (position #\/ addr))
	 (mask #xffffffff)
	 (network (socket:dotted-to-ipaddr 
		   (subseq addr 0 (or slashpos (length addr))))))
    (if* slashpos
       then
	    (setf addr (subseq addr (1+ slashpos)))
	    (setf mask 
	      (if (position #\. addr)
		  (socket:dotted-to-ipaddr addr)
		(masklength-to-mask addr)))
	    (setf network (logand network mask)))
    (make-network-address
     :network network
     :mask mask)))

(defun masklength-to-mask (value)
  (if (stringp value)
      (setf value (parse-integer value)))
  (if (or (< value 0) (> value 32))
      (error "Invalid mask length: ~A" value))
  (- #xffffffff (1- (expt 2 (- 32 value)))))

  
(defun addr-in-network-p (addr net)
  (if (stringp addr)
      (setf addr (socket:dotted-to-ipaddr addr)))
  (= (logand addr (network-address-mask net))
     (network-address-network net)))

;; The best match is the one that has the longest network
;; mask (i.e., most on-bits.. which means.. the largest integer value)
(defun best-network-match (addr nets)
  (if (stringp addr)
      (setf addr (socket:dotted-to-ipaddr addr)))
  (let (best)
    (dolist (net nets)
      (if (addr-in-network-p addr net)
	  (if (null best)
	      (setf best net)
	    (if (> (network-address-mask net)
		   (network-address-mask best))
		(setf best net)))))
    best))
