(load "config.cl")
(setq *debug* t)
(setq *ftpport* 8021)
(load "ftpd.fasl")
(trace excl::filesys-type)
(open-logs)
(standalone-main)
