dnl Check for readline and dependencies
dnl Copyright (C) 2004, 2005 Free Software Foundation, Inc.
dnl
dnl This file is free software, distributed under the terms of the GNU
dnl General Public License.  As a special exception to the GNU General
dnl Public License, this file may be distributed as part of a program
dnl that contains a configuration script generated by Autoconf, under
dnl the same distribution terms as the rest of that program.
dnl
dnl Defines HAVE_LIBREADLINE to 1 if a working readline setup is
dnl found, and sets @LIBREADLINE@ to the necessary libraries.

AC_DEFUN([GNUPG_CHECK_READLINE],
[
  AC_ARG_WITH(readline,
     AC_HELP_STRING([--with-readline=DIR],
	[look for the readline library in DIR]),
     [_do_readline=$withval],[_do_readline=yes])

  if test "$_do_readline" != "no" ; then
     if test -d "$withval" ; then
        CPPFLAGS="${CPPFLAGS} -I$withval/include"
        LDFLAGS="${LDFLAGS} -L$withval/lib"
     fi

     for _termcap in "" "-ltermcap" "-lcurses" "-lncurses" ; do
        _readline_save_libs=$LIBS
        _combo="-lreadline${_termcap:+ $_termcap}"
        LIBS="$LIBS $_combo"

        AC_MSG_CHECKING([whether readline via \"$_combo\" is present and sane])

        AC_LINK_IFELSE(AC_LANG_PROGRAM([
#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
],[
rl_completion_func_t *completer;
add_history("foobar");
rl_catch_signals=0;
rl_inhibit_completion=0;
rl_attempted_completion_function=NULL;
rl_completion_matches(NULL,NULL);
]),_found_readline=yes,_found_readline=no)

        AC_MSG_RESULT([$_found_readline])

        LIBS=$_readline_save_libs

        if test $_found_readline = yes ; then
           AC_DEFINE(HAVE_LIBREADLINE,1,
	      [Define to 1 if you have a fully functional readline library.])
           AC_SUBST(LIBREADLINE,$_combo)
           break
        fi
     done

     unset _termcap
     unset _readline_save_libs
     unset _combo
     unset _found_readline
  fi
])dnl
