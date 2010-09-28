<!DOCTYPE style-sheet PUBLIC "-//James Clark//DTD DSSSL Style Sheet//EN" [
<!ENTITY dbstyle PUBLIC "-//Norman Walsh//DOCUMENT DocBook HTML Stylesheet//EN" CDATA DSSSL>
]>

<style-sheet>
<style-specification use="docbook">
<style-specification-body>

;; These are some customizations to the standard HTML output produced by the
;; Modular DocBook Stylesheets.
;; I've copied parts of a few functions from the stylesheets so these should
;; be checked occasionally to ensure they are up to date.
;;
;; The last check was with version 1.40 of the stylesheets.
;; It will not work with versions < 1.19 since the $shade-verbatim-attr$
;; function was added then. Versions 1.19 to 1.39 may be OK, if you're lucky!

;;(define %generate-book-toc% #f)


;; The email content should not line wrap in HTML, that looks ugly.
;; (okay there shouldn't be whitespace in there but when people want
;; to avoid an @ they can fill in all kinds of things).
(element email 
  ($mono-seq$ 
   (make sequence 
     (make element gi: "NOBR"
	   (literal "&#60;")
	   (make element gi: "A"
		 attributes: (list (list "HREF" 
					 (string-append "mailto:" 
							(data (current-node)))))
		 (process-children))
	   (literal "&#62;")))))


;; We want to have some control over how sections are split up into
;; separate pages.
(define (chunk-element-list)
  (list (normalize "preface")
        (normalize "chapter")
        (normalize "appendix")
        (normalize "article")
        (normalize "glossary")
        (normalize "bibliography")
        (normalize "index")
        (normalize "colophon")
        (normalize "setindex")
        (normalize "reference")
        (normalize "refentry")
        (normalize "part")
;; Commented out to prevent splitting up every section into its own document
;;        (normalize "sect1")
;;        (normalize "section")
        (normalize "book") ;; just in case nothing else matches...
        (normalize "set")  ;; sets are definitely chunks...
        ))


;; If a Chapter has role="no-toc" we don't generate a table of contents.
;; This is useful if a better contents page has been added manually, e.g. for
;; the GTK+ Widgets & Objects page. (But it is a bit of a hack.)
(define ($generate-chapter-toc$)
  (not (equal? (attribute-string (normalize "role") (current-node)) "no-toc")))

(define %chapter-autolabel% 
  ;; Are chapters enumerated?
  #t)

(define %section-autolabel% 
  ;; Are sections enumerated?
  #t)

(define %use-id-as-filename% #t)

(define %html-ext% ".html")

(define %shade-verbatim% #t)

(define (book-titlepage-separator side)
  (empty-sosofo))


(define ($shade-verbatim-attr$)
  ;; Attributes used to create a shaded verbatim environment.
  (list
   (list "WIDTH" "100%")
   (list "BORDER" "0")
   (list "BGCOLOR" "#eaeaf0")))


;; This overrides the refsect2 definition (copied from 1.20, dbrfntry.dsl).
;; It puts a horizontal rule before each function/struct/... description,
;; except the first one in the refsect1.
(element refsect2
  (make sequence
    (if (first-sibling?)
	(empty-sosofo)
	(make empty-element gi: "HR"))
    ($block-container$)))

;; Override the book declaration, so that we generate a crossreference
;; for the book

(element book 
  (let* ((bookinfo  (select-elements (children (current-node)) (normalize "bookinfo")))
	 (ititle   (select-elements (children bookinfo) (normalize "title")))
	 (title    (if (node-list-empty? ititle)
		       (select-elements (children (current-node)) (normalize "title"))
		       (node-list-first ititle)))
	 (nl       (titlepage-info-elements (current-node) bookinfo))
	 (tsosofo  (with-mode head-title-mode
		     (process-node-list title)))
	 (dedication (select-elements (children (current-node)) (normalize "dedication"))))
    (make sequence
     (html-document 
      tsosofo
      (make element gi: "DIV"
	    attributes: '(("CLASS" "BOOK"))
	    (if %generate-book-titlepage%
		(make sequence
		  (book-titlepage nl 'recto)
		  (book-titlepage nl 'verso))
		(empty-sosofo))
	    
	    (if (node-list-empty? dedication)
		(empty-sosofo)
		(with-mode dedication-page-mode
		  (process-node-list dedication)))
	    
	    (if (not (generate-toc-in-front))
		(process-children)
		(empty-sosofo))
	    
	    (if %generate-book-toc%
		(build-toc (current-node) (toc-depth (current-node)))
		(empty-sosofo))
	    
	    ;;	  (let loop ((gilist %generate-book-lot-list%))
	    ;;	    (if (null? gilist)
	    ;;		(empty-sosofo)
	    ;;		(if (not (node-list-empty? 
	    ;;			  (select-elements (descendants (current-node))
	    ;;					   (car gilist))))
	    ;;		    (make sequence
	    ;;		      (build-lot (current-node) (car gilist))
	    ;;		      (loop (cdr gilist)))
	    ;;		    (loop (cdr gilist)))))
	  
	    (if (generate-toc-in-front)
		(process-children)
		(empty-sosofo))))
     (make entity 
       system-id: "index.sgml"
       (with-mode generate-index-mode
	 (process-children))))))

;; Mode for generating cross references

(define (process-child-elements)
  (process-node-list
   (node-list-map (lambda (snl)
                    (if (equal? (node-property 'class-name snl) 'element)
                        snl
                        (empty-node-list)))
                  (children (current-node)))))

(mode generate-index-mode
  (element anchor
    (if (attribute-string "href" (current-node))
	(empty-sosofo)
	(make formatting-instruction data:
	      (string-append "\less-than-sign;ANCHOR id =\""
			     (attribute-string "id" (current-node))
			     "\" href=\""
			     (href-to (current-node))
			     "\"\greater-than-sign;
"))))

  ;; We also want to be able to link to complete RefEntry.
  (element refentry
    (make sequence
      (make formatting-instruction data:
	    (string-append "\less-than-sign;ANCHOR id =\""
			   (attribute-string "id" (current-node))
			   "\" href=\""
			   (href-to (current-node))
			   "\"\greater-than-sign;
"))
      (process-child-elements)))

  (default
    (process-child-elements)))

;; For hypertext links for which no target is found in the document, we output
;; our own special tag which we use later to resolve cross-document links.
(element link 
  (let* ((target (element-with-id (attribute-string (normalize "linkend")))))
    (if (node-list-empty? target)
      (make element gi: "GTKDOCLINK"
	    attributes: (list
			 (list "HREF" (attribute-string (normalize "linkend"))))
            (process-children))
      (make element gi: "A"
            attributes: (list
                         (list "HREF" (href-to target)))
            (process-children)))))




(define ($section-body$)
  (make sequence
    (make empty-element gi: "BR"
	  attributes: (list (list "CLEAR" "all")))
    (make element gi: "DIV"
	  attributes: (list (list "CLASS" (gi)))
	  ($section-separator$)
	  ($section-title$)
	  (process-children))))

;; We want to use a stylesheet!
(define %css-decoration%
  ;; Enable CSS decoration of elements
  #t)
(define %stylesheet%
  ;; Name of the stylesheet to use
  "stylesheet.css")


;; I want my own graphics with admonitions.
(define %admon-graphics%
  ;; Use graphics in admonitions?
  #t)
(define %admon-graphics-path%
  ;; Path to admonition graphics
  "images/")


;; Some stuff I really didn't like -- italics are
;; pretty hard to read most of the time. Don't use
;; them for parameter names and structure fields.
(element parameter ($mono-seq$))
(element structfield ($mono-seq$))

;; And don't use italics for emphasis either, just
;; use bold text.
(element emphasis
  (let* ((class (if (and (attribute-string (normalize "role"))
			 %emphasis-propagates-style%)
		    (attribute-string (normalize "role"))
		    "emphasis")))
    (make element gi: "SPAN"
	  attributes: (list (list "CLASS" class))
	  (if (and (attribute-string (normalize "role"))
		   (or (equal? (attribute-string (normalize "role")) "strong")
		       (equal? (attribute-string (normalize "role")) "bold")))
	      ($bold-seq$) ($bold-seq$)))))

</style-specification-body>
</style-specification>
<external-specification id="docbook" document="dbstyle">
</style-sheet>
