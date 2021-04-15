\ Copyright (c) 2003 Scott Long <scottl@FreeBSD.org>
\ Copyright (c) 2003 Aleksander Fafula <alex@fafula.com>
\ Copyright (c) 2006-2015 Devin Teske <dteske@FreeBSD.org>
\ Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
\ All rights reserved.
\
\ Redistribution and use in source and binary forms, with or without
\ modification, are permitted provided that the following conditions
\ are met:
\ 1. Redistributions of source code must retain the above copyright
\    notice, this list of conditions and the following disclaimer.
\ 2. Redistributions in binary form must reproduce the above copyright
\    notice, this list of conditions and the following disclaimer in the
\    documentation and/or other materials provided with the distribution.
\
\ THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
\ ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
\ IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
\ ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
\ FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
\ DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
\ OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
\ HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
\ LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
\ OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
\ SUCH DAMAGE.

marker task-menu.4th

\ Frame drawing
include /boot/forth/frames.4th

vocabulary menu-infrastructure
vocabulary menu-namespace
vocabulary menu-command-helpers

only forth also menu-infrastructure definitions

f_double        \ Set frames to double (see frames.4th). Replace with
                \ f_single if you want single frames.
46 constant dot \ ASCII definition of a period (in decimal)

 5 constant menu_default_x         \ default column position of timeout
10 constant menu_default_y         \ default row position of timeout msg
 4 constant menu_timeout_default_x \ default column position of timeout
23 constant menu_timeout_default_y \ default row position of timeout msg
10 constant menu_timeout_default   \ default timeout (in seconds)

\ Customize the following values with care

  1 constant menu_start \ Numerical prefix of first menu item
dot constant bullet     \ Menu bullet (appears after numerical prefix)
  5 constant menu_x     \ Row position of the menu (from the top)
 10 constant menu_y     \ Column position of the menu (from left side)

\ Menu Appearance
variable menuidx   \ Menu item stack for number prefixes
variable menurow   \ Menu item stack for positioning
variable menubllt  \ Menu item bullet

\ Menu Positioning
variable menuX     \ Menu X offset (columns)
variable menuY     \ Menu Y offset (rows)

\ Menu-item elements
variable menurebootadded

\ Menu timer [count-down] variables
variable menu_timeout_enabled \ timeout state (internal use only)
variable menu_time            \ variable for tracking the passage of time
variable menu_timeout         \ determined configurable delay duration
variable menu_timeout_x       \ column position of timeout message
variable menu_timeout_y       \ row position of timeout message

only forth also menu-namespace definitions

\ Menu-item key association/detection
variable menukey1
variable menukey2
variable menukey3
variable menukey4
variable menukey5
variable menukey6
variable menukey7
variable menukey8
variable menureboot
variable menuacpi
variable menuosconsole
variable menukmdb
variable menuoptions

\ Menu initialization status variables
variable init_state1
variable init_state2
variable init_state3
variable init_state4
variable init_state5
variable init_state6
variable init_state7
variable init_state8

\ Boolean option status variables
variable toggle_state1
variable toggle_state2
variable toggle_state3
variable toggle_state4
variable toggle_state5
variable toggle_state6
variable toggle_state7
variable toggle_state8

\ Array option status variables
variable cycle_state1
variable cycle_state2
variable cycle_state3
variable cycle_state4
variable cycle_state5
variable cycle_state6
variable cycle_state7
variable cycle_state8

\ Containers for storing the initial caption text
create init_text1 64 allot
create init_text2 64 allot
create init_text3 64 allot
create init_text4 64 allot
create init_text5 64 allot
create init_text6 64 allot
create init_text7 64 allot
create init_text8 64 allot

only forth definitions

: arch-i386? ( -- BOOL ) \ Returns TRUE (-1) on i386, FALSE (0) otherwise.
	s" arch-i386" environment? dup if
		drop
	then
;

: acpipresent? ( -- flag ) \ Returns TRUE if ACPI is present, FALSE otherwise
	s" hint.acpi.0.rsdp" getenv
	dup -1 = if
		drop false exit
	then
	2drop
	true
;

: acpienabled? ( -- flag ) \ Returns TRUE if ACPI is enabled, FALSE otherwise
	s" hint.acpi.0.disabled" getenv
	dup -1 <> if
		s" 0" compare 0<> if
			false exit
		then
	else
		drop
	then
	true
;

: +c! ( N C-ADDR/U K -- C-ADDR/U )
	3 pick 3 pick	( n c-addr/u k -- n c-addr/u k n c-addr )
	rot + c!	( n c-addr/u k n c-addr -- n c-addr/u )
	rot drop	( n c-addr/u -- c-addr/u )
;

only forth also menu-namespace definitions

\ Forth variables
: namespace     ( C-ADDR/U N -- ) also menu-namespace +c! evaluate previous ;
: menukeyN      ( N -- ADDR )   s" menukeyN"       7 namespace ;
: init_stateN   ( N -- ADDR )   s" init_stateN"   10 namespace ;
: toggle_stateN ( N -- ADDR )   s" toggle_stateN" 12 namespace ;
: cycle_stateN  ( N -- ADDR )   s" cycle_stateN"  11 namespace ;
: init_textN    ( N -- C-ADDR ) s" init_textN"     9 namespace ;

\ Environment variables
: menu_init[x]       ( N -- C-ADDR/U )   s" menu_init[x]"       10 +c! ;
: menu_command[x]    ( N -- C-ADDR/U )   s" menu_command[x]"    13 +c! ;
: menu_caption[x]    ( N -- C-ADDR/U )   s" menu_caption[x]"    13 +c! ;
: ansi_caption[x]    ( N -- C-ADDR/U )   s" ansi_caption[x]"    13 +c! ;
: menu_keycode[x]    ( N -- C-ADDR/U )   s" menu_keycode[x]"    13 +c! ;
: toggled_text[x]    ( N -- C-ADDR/U )   s" toggled_text[x]"    13 +c! ;
: toggled_ansi[x]    ( N -- C-ADDR/U )   s" toggled_ansi[x]"    13 +c! ;
: menu_caption[x][y] ( N M -- C-ADDR/U ) s" menu_caption[x][y]" 16 +c! 13 +c! ;
: ansi_caption[x][y] ( N M -- C-ADDR/U ) s" ansi_caption[x][y]" 16 +c! 13 +c! ;

also menu-infrastructure definitions

\ This function prints a menu item at menuX (row) and menuY (column), returns
\ the incremental decimal ASCII value associated with the menu item, and
\ increments the cursor position to the next row for the creation of the next
\ menu item. This function is called by the menu-create function. You need not
\ call it directly.
\
: printmenuitem ( menu_item_str -- ascii_keycode )

	loader_color? if [char] ^ escc! then

	menurow dup @ 1+ swap ! ( increment menurow )
	menuidx dup @ 1+ swap ! ( increment menuidx )

	\ Calculate the menuitem row position
	menurow @ menuY @ +

	\ Position the cursor at the menuitem position
	dup menuX @ swap at-xy

	\ Print the value of menuidx
	loader_color? dup ( -- bool bool )
	if b then
	menuidx @ .
	if me then

	\ Move the cursor forward 1 column
	dup menuX @ 1+ swap at-xy

	menubllt @ emit	\ Print the menu bullet using the emit function

	\ Move the cursor to the 3rd column from the current position
	\ to allow for a space between the numerical prefix and the
	\ text caption
	menuX @ 3 + swap at-xy

	\ Print the menu caption (we expect a string to be on the stack
	\ prior to invoking this function)
	type

	\ Here we will add the ASCII decimal of the numerical prefix
	\ to the stack (decimal ASCII for `1' is 49) as a "return value"
	menuidx @ 48 +
;

: delim? ( C -- BOOL )
	dup  32 =		( c -- c bool )		\ [sp] space
	over  9 = or		( c bool -- c bool )	\ [ht] horizontal tab
	over 10 = or		( c bool -- c bool )	\ [nl] newline
	over 13 = or		( c bool -- c bool )	\ [cr] carriage return
	over [char] , =	or	( c bool -- c bool )	\ comma
	swap drop		( c bool -- bool )	\ return boolean
;

\ illumos kernel acpi-user-options has following values:
\ default:	0 - system will enable acpi based on bios date
\ on:		1 - acpi is set on
\ off:		2 - acpi is set off
\ madt:		4 - use only MADT
\ legacy:	8 - use legacy mode

: acpi-captions ( N -- )
  \ first entry
  dup s" [A]CPI................ default" rot 48 menu_caption[x][y] setenv
  dup s" ^[1mA^[mCPI.............. ^[32;7mdefault^[m" rot 48 ansi_caption[x][y] setenv

  dup s" [A]CPI................ On" rot 49 menu_caption[x][y] setenv
  dup s" ^[1mA^[mCPI.............. ^[34;1mOn^[m" rot 49 ansi_caption[x][y] setenv

  dup s" [A]CPI................ Off" rot 50 menu_caption[x][y] setenv
  dup s" ^[1mA^[mCPI.............. ^[34;1mOff^[m" rot 50 ansi_caption[x][y] setenv

  dup s" [A]CPI................ MADT" rot 51 menu_caption[x][y] setenv
  dup s" ^[1mA^[mCPI.............. ^[34;1mMADT^[m" rot 51 ansi_caption[x][y] setenv

  dup s" [A]CPI................ Legacy" rot 52 menu_caption[x][y] setenv
  s" ^[1mA^[mCPI.............. ^[34;1mLegacy^[m" rot 52 ansi_caption[x][y] setenv
;

\ illumos console has following values:
\ text, ttya, ttyb, ttyc, ttyd

: osconsole-captions ( N -- )
  \ first entry
  dup s" Os[C]onsole........... text" rot 48 menu_caption[x][y] setenv
  dup s" Os^[1mC^[monsole............ ^[32;7mtext^[m" rot 48 ansi_caption[x][y] setenv

  dup s" Os[C]onsole........... ttya" rot 49 menu_caption[x][y] setenv
  dup s" Os^[1mC^[monsole............ ^[34;1mttya^[m" rot 49 ansi_caption[x][y] setenv

  dup s" Os[C]onsole........... ttyb" rot 50 menu_caption[x][y] setenv
  dup s" Os^[1mC^[monsole............ ^[34;1mttyb^[m" rot 50 ansi_caption[x][y] setenv

  dup s" Os[C]onsole........... ttyc" rot 51 menu_caption[x][y] setenv
  dup s" Os^[1mC^[monsole............ ^[34;1mttyc^[m" rot 51 ansi_caption[x][y] setenv

  dup s" Os[C]onsole........... ttyd" rot 52 menu_caption[x][y] setenv
  s" Os^[1mC^[monsole............ ^[34;1mttyd^[m" rot 52 ansi_caption[x][y] setenv
;

\ kmdb options are as follows
\ default:	0 - disabled
\		1 - boot with -k option
\		2 - as 1 + configure NMI to drop to kmdb
\		3 - boot with -k and -d options
\		4 - as 3 + configure NMI to drop to kmdb

: kmdb-captions ( N -- )
  \ first entry
  dup s" [k]mdb Mode........... Off" rot 48 menu_caption[x][y] setenv
  dup s" ^[1mk^[mmdb Mode............. ^[34;1mOff^[m" rot 48 ansi_caption[x][y] setenv

  dup s" [k]mdb Mode........... Loaded" rot 49 menu_caption[x][y] setenv
  dup s" ^[1mk^[mmdb Mode............. ^[32;7mLoaded^[m" rot 49 ansi_caption[x][y] setenv

  dup s" [k]mdb Mode........... On NMI" rot 50 menu_caption[x][y] setenv
  dup s" ^[1mk^[mmdb Mode............. ^[32;7mOn NMI^[m" rot 50 ansi_caption[x][y] setenv

  dup s" [k]mdb Mode........... On Boot" rot 51 menu_caption[x][y] setenv
  dup s" ^[1mk^[mmdb Mode............. ^[32;7mOn Boot^[m" rot 51 ansi_caption[x][y] setenv

  dup s" [k]mdb Mode........... On Boot/NMI" rot 52 menu_caption[x][y] setenv
  s" ^[1mk^[mmdb Mode............. ^[32;7mOn Boot/NMI^[m" rot 52 ansi_caption[x][y] setenv
;

: set-captions ( x y - x y )
	\ Set the current non-ANSI caption
	2dup swap dup ( x y -- x y y x x )
	s" set menu_caption[x]=$menu_caption[x][y]"
	17 +c! 34 +c! 37 +c! evaluate
	( x y y x x c-addr/u -- x y  )

	\ Set the current ANSI caption
	2dup swap dup ( x y -- x y y x x )
	s" set ansi_caption[x]=$ansi_caption[x][y]"
	17 +c! 34 +c! 37 +c! evaluate
	( x y y x x c-addr/u -- x y )
;

\ This function creates the list of menu items. This function is called by the
\ menu-display function. You need not call it directly.
\
: menu-create ( -- )

	\ Print the frame caption at (x,y)
	s" loader_menu_title" getenv dup -1 = if
		drop s" Welcome to illumos"
	then
	TRUE ( use default alignment )
	s" loader_menu_title_align" getenv dup -1 <> if
		2dup s" left" compare-insensitive 0= if ( 1 )
			2drop ( c-addr/u ) drop ( bool )
			menuX @ menuY @ 1-
			FALSE ( don't use default alignment )
		else ( 1 ) 2dup s" right" compare-insensitive 0= if ( 2 )
			2drop ( c-addr/u ) drop ( bool )
			menuX @ 42 + 4 - over - menuY @ 1-
			FALSE ( don't use default alignment )
		else ( 2 ) 2drop ( c-addr/u ) then ( 1 ) then
	else
		drop ( getenv cruft )
	then
	if ( use default center alignement? )
		menuX @ 19 + over 2 / - menuY @ 1-
	then
	at-xy type

	\ If $menu_init is set, evaluate it (allowing for whole menus to be
	\ constructed dynamically -- as this function could conceivably set
	\ the remaining environment variables to construct the menu entirely).
	\
	s" menu_init" getenv dup -1 <> if
		evaluate
	else
		drop
	then

	\ Print our menu options with respective key/variable associations.
	\ `printmenuitem' ends by adding the decimal ASCII value for the
	\ numerical prefix to the stack. We store the value left on the stack
	\ to the key binding variable for later testing against a character
	\ captured by the `getkey' function.

	\ Note that any menu item beyond 9 will have a numerical prefix on the
	\ screen consisting of the first digit (ie. 1 for the tenth menu item)
	\ and the key required to activate that menu item will be the decimal
	\ ASCII of 48 plus the menu item (ie. 58 for the tenth item, aka. `:')
	\ which is misleading and not desirable.
	\
	\ Thus, we do not allow more than 8 configurable items on the menu
	\ (with "Reboot" as the optional ninth and highest numbered item).

	\
	\ Initialize the OsConsole option status.
	\
	0 menuosconsole !
	s" menu_osconsole" getenv -1 <> if
		c@ dup 48 > over 57 < and if ( '1' <= c1 <= '8' )
			dup menuosconsole !
			dup osconsole-captions

			s" init_osconsole" evaluate

			\ Get the current cycle state (entry to use)
			s" osconsole_state" evaluate @ 48 + ( n -- n y )

			set-captions

			\ Initialize cycle state from stored value
			48 - ( n y -- n k )
			s" init_cyclestate" evaluate ( n k -- n )

			\ Set $os_console
			s" activate_osconsole" evaluate ( n -- n )
		then
		drop
	then

	\
	\ Initialize the ACPI option status.
	\
	0 menuacpi !
	s" menu_acpi" getenv -1 <> if
		c@ dup 48 > over 57 < and if ( '1' <= c1 <= '8' )
			dup menuacpi !
			dup acpi-captions

			s" init_acpi" evaluate

			\ Get the current cycle state (entry to use)
			s" acpi_state" evaluate @ 48 + ( n -- n y )

			set-captions

			\ Initialize cycle state from stored value
			48 - ( n y -- n k )
			s" init_cyclestate" evaluate ( n k -- n )

			\ Set $acpi-user-options
			s" activate_acpi" evaluate ( n -- n )
		then
		drop
	then

	\
	\ Initialize the kmdb option status.
	\
	0 menukmdb !
	s" menu_kmdb" getenv -1 <> if
		c@ dup 48 > over 57 < and if ( '1' <= c1 <= '8' )
			dup menukmdb !
			dup kmdb-captions

			s" init_kmdb" evaluate

			\ Get the current cycle state (entry to use)
			s" kmdb_state" evaluate @ 48 + ( n -- n y )

			set-captions

			\ Initialize cycle state from stored value
			48 - ( n y -- n k )
			s" init_cyclestate" evaluate ( n k -- n )

			\ Activate the current option
			s" activate_kmdb" evaluate ( n -- n )
		then
		drop
	then

	\
	\ Initialize the menu_options visual separator.
	\
	0 menuoptions !
	s" menu_options" getenv -1 <> if
		c@ dup 48 > over 57 < and if ( '1' <= c1 <= '8' )
			menuoptions !
		else
			drop
		then
	then

	\ Initialize "Reboot" menu state variable (prevents double-entry)
	false menurebootadded !

	menu_start
	1- menuidx !    \ Initialize the starting index for the menu
	0 menurow !     \ Initialize the starting position for the menu

	49 \ Iterator start (loop range 49 to 56; ASCII '1' to '8')
	begin
		\ If the "Options:" separator, print it.
		dup menuoptions @ = if
			\ Optionally add a reboot option to the menu
			s" menu_reboot" getenv -1 <> if
				drop
				s" Reboot" printmenuitem menureboot !
				true menurebootadded !
			then

			menuX @
			menurow @ 2 + menurow !
			menurow @ menuY @ +
			at-xy
			s" menu_optionstext" getenv dup -1 <> if
				type
			else
				drop ." Options:"
			then
		then

		\ make sure we have not already initialized this item
		dup init_stateN dup @ 0= if
			1 swap !

			\ If this menuitem has an initializer, run it
			dup menu_init[x]
			getenv dup -1 <> if
				evaluate
			else
				drop
			then
		else
			drop
		then

		dup
		loader_color? if
			ansi_caption[x]
		else
			menu_caption[x]
		then

		dup -1 <> if
			\ test for environment variable
			getenv dup -1 <> if
				printmenuitem ( c-addr/u -- n )
				dup menukeyN !
			else
				drop
			then
		else
			drop
		then

		1+ dup 56 > \ add 1 to iterator, continue if less than 57
	until
	drop \ iterator

	\ Optionally add a reboot option to the menu
	menurebootadded @ true <> if
		s" menu_reboot" getenv -1 <> if
			drop       \ no need for the value
			s" Reboot" \ menu caption (required by printmenuitem)

			printmenuitem
			menureboot !
		else
			0 menureboot !
		then
	then
;

\ Takes an integer on the stack and updates the timeout display.
\
: menu-timeout-update ( N -- )

	\ Enforce minimum
	dup 0 < if drop 0 then

	menu_timeout_x @ menu_timeout_y @ at-xy \ position cursor

	dup 0> if
		s" Autoboot in " type
		dup . s" second" type
		1 > if [char] s emit then
		s" . [Space] to pause " type
	else
		drop 40 spaces \ erase message
	then

	at-bl
;

\ This function blocks program flow (loops forever) until a key is pressed.
\ The key that was pressed is added to the top of the stack in the form of its
\ decimal ASCII representation. This function is called by the menu-display
\ function. You need not call it directly.
\ note, the esc sequences will be dropped, this needs to be changed if
\ menu is built based on arrow keys.
\
: getkey ( -- ascii_keycode )

	begin \ loop forever

		menu_timeout_enabled @ 1 = if
			( -- )
			seconds ( get current time: -- N )
			dup menu_time @ <> if ( has time elapsed?: N N N -- N )

				\ At least 1 second has elapsed since last loop
				\ so we will decrement our "timeout" (really a
				\ counter, insuring that we do not proceed too
				\ fast) and update our timeout display.

				menu_time ! ( update time record: N -- )
				menu_timeout @ ( "time" remaining: -- N )
				dup 0> if ( greater than 0?: N N 0 -- N )
					1- ( decrement counter: N -- N )
					dup menu_timeout !
						( re-assign: N N Addr -- N )
				then
				( -- N )

				dup 0= swap 0< or if ( N <= 0?: N N -- )
					\ halt the timer
					0 menu_timeout ! ( 0 Addr -- )
					0 menu_timeout_enabled ! ( 0 Addr -- )
				then

				\ update the timer display ( N -- )
				menu_timeout @ menu-timeout-update

				menu_timeout @ 0= if
					\ We've reached the end of the timeout
					\ (user did not cancel by pressing ANY
					\ key)

					s" menu_timeout_command"  getenv dup
					-1 = if
						drop \ clean-up
					else
						evaluate
					then
				then

			else ( -- N )
				\ No [detectable] time has elapsed (in seconds)
				drop ( N -- )
			then
			( -- )
		then

		key? if \ Was a key pressed? (see loader(8))

			\ An actual key was pressed (if the timeout is running,
			\ kill it regardless of which key was pressed)
			menu_timeout @ 0<> if
				0 menu_timeout !
				0 menu_timeout_enabled !

				\ clear screen of timeout message
				0 menu-timeout-update
			then

			\ get the key that was pressed and exit (if we
			\ get a non-zero ASCII code)
			key dup 0<> if
				dup 0x1b = if
					key? if ( is it sequence? )
						drop
						begin
							key?
						while
							key drop
						repeat
					else
						exit
					then
				else
					exit
				then
			else
				drop
			then
		then
		50 ms \ sleep for 50 milliseconds (see loader(8))

	again
;

: menu-erase ( -- ) \ Erases menu and resets positioning variable to position 1.

	\ Clear the screen area associated with the interactive menu
	menuX @ menuY @
	2dup at-xy 38 spaces 1+		2dup at-xy 38 spaces 1+
	2dup at-xy 38 spaces 1+		2dup at-xy 38 spaces 1+
	2dup at-xy 38 spaces 1+		2dup at-xy 38 spaces 1+
	2dup at-xy 38 spaces 1+		2dup at-xy 38 spaces 1+
	2dup at-xy 38 spaces 1+		2dup at-xy 38 spaces 1+
	2dup at-xy 38 spaces 1+		2dup at-xy 38 spaces
	2drop

	\ Reset the starting index and position for the menu
	menu_start 1- menuidx !
	0 menurow !
;

only forth
also menu-infrastructure
also menu-namespace
also menu-command-helpers definitions

: toggle_menuitem ( N -- N ) \ toggles caption text and internal menuitem state

	\ ASCII numeral equal to user-selected menu item must be on the stack.
	\ We do not modify the stack, so the ASCII numeral is left on top.

	dup init_textN c@ 0= if
		\ NOTE: no need to check toggle_stateN since the first time we
		\ are called, we will populate init_textN. Further, we don't
		\ need to test whether menu_caption[x] (ansi_caption[x] when
		\ loader_color?=1) is available since we would not have been
		\ called if the caption was NULL.

		\ base name of environment variable
		dup ( n -- n n ) \ key pressed
		loader_color? if
			ansi_caption[x]
		else
			menu_caption[x]
		then
		getenv dup -1 <> if

			2 pick ( n c-addr/u -- n c-addr/u n )
			init_textN ( n c-addr/u n -- n c-addr/u c-addr )

			\ now we have the buffer c-addr on top
			\ ( followed by c-addr/u of current caption )

			\ Copy the current caption into our buffer
			2dup c! -rot \ store strlen at first byte
			begin
				rot 1+    \ bring alt addr to top and increment
				-rot -rot \ bring buffer addr to top
				2dup c@ swap c! \ copy current character
				1+     \ increment buffer addr
				rot 1- \ bring buffer len to top and decrement
				dup 0= \ exit loop if buffer len is zero
			until
			2drop \ buffer len/addr
			drop  \ alt addr

		else
			drop
		then
	then

	\ Now we are certain to have init_textN populated with the initial
	\ value of menu_caption[x] (ansi_caption[x] with loader_color enabled).
	\ We can now use init_textN as the untoggled caption and
	\ toggled_text[x] (toggled_ansi[x] with loader_color enabled) as the
	\ toggled caption and store the appropriate value into menu_caption[x]
	\ (again, ansi_caption[x] with loader_color enabled). Last, we'll
	\ negate the toggled state so that we reverse the flow on subsequent
	\ calls.

	dup toggle_stateN @ 0= if
		\ state is OFF, toggle to ON

		dup ( n -- n n ) \ key pressed
		loader_color? if
			toggled_ansi[x]
		else
			toggled_text[x]
		then
		getenv dup -1 <> if
			\ Assign toggled text to menu caption
			2 pick ( n c-addr/u -- n c-addr/u n ) \ key pressed
			loader_color? if
				ansi_caption[x]
			else
				menu_caption[x]
			then
			setenv
		else
			\ No toggled text, keep the same caption
			drop ( n -1 -- n ) \ getenv cruft
		then

		true \ new value of toggle state var (to be stored later)
	else
		\ state is ON, toggle to OFF

		dup init_textN count ( n -- n c-addr/u )

		\ Assign init_textN text to menu caption
		2 pick ( n c-addr/u -- n c-addr/u n ) \ key pressed
		loader_color? if
			ansi_caption[x]
		else
			menu_caption[x]
		then
		setenv

		false \ new value of toggle state var (to be stored below)
	then

	\ now we'll store the new toggle state (on top of stack)
	over toggle_stateN !
;

: cycle_menuitem ( N -- N ) \ cycles through array of choices for a menuitem

	\ ASCII numeral equal to user-selected menu item must be on the stack.
	\ We do not modify the stack, so the ASCII numeral is left on top.

	dup cycle_stateN dup @ 1+ \ get value and increment

	\ Before assigning the (incremented) value back to the pointer,
	\ let's test for the existence of this particular array element.
	\ If the element exists, we'll store index value and move on.
	\ Otherwise, we'll loop around to zero and store that.

	dup 48 + ( n addr k -- n addr k k' )
	         \ duplicate array index and convert to ASCII numeral

	3 pick swap ( n addr k k' -- n addr k n k' ) \ (n,k') as (x,y)
	loader_color? if
		ansi_caption[x][y]
	else
		menu_caption[x][y]
	then
	( n addr k n k' -- n addr k c-addr/u )

	\ Now test for the existence of our incremented array index in the
	\ form of $menu_caption[x][y] ($ansi_caption[x][y] with loader_color
	\ enabled) as set in loader.rc(5), et. al.

	getenv dup -1 = if
		\ No caption set for this array index. Loop back to zero.

		drop ( n addr k -1 -- n addr k ) \ getenv cruft
		drop 0 ( n addr k -- n addr 0 )  \ new value to store later

		2 pick [char] 0 ( n addr 0 -- n addr 0 n 48 ) \ (n,48) as (x,y)
		loader_color? if
			ansi_caption[x][y]
		else
			menu_caption[x][y]
		then
		( n addr 0 n 48 -- n addr 0 c-addr/u )
		getenv dup -1 = if
			\ Highly unlikely to occur, but to ensure things move
			\ along smoothly, allocate a temporary NULL string
			drop ( cruft ) s" "
		then
	then

	\ At this point, we should have the following on the stack (in order,
	\ from bottom to top):
	\
	\    n        - Ascii numeral representing the menu choice (inherited)
	\    addr     - address of our internal cycle_stateN variable
	\    k        - zero-based number we intend to store to the above
	\    c-addr/u - string value we intend to store to menu_caption[x]
	\               (or ansi_caption[x] with loader_color enabled)
	\
	\ Let's perform what we need to with the above.

	\ Assign array value text to menu caption
	4 pick ( n addr k c-addr/u -- n addr k c-addr/u n )
	loader_color? if
		ansi_caption[x]
	else
		menu_caption[x]
	then
	setenv

	swap ! ( n addr k -- n ) \ update array state variable
;

only forth definitions also menu-infrastructure

\ Erase and redraw the menu. Useful if you change a caption and want to
\ update the menu to reflect the new value.
\
: menu-redraw ( -- )
	menu-erase
	menu-create
;

: menu-box ( -- )
	\ Interpret a custom frame type for the menu
	TRUE ( draw a box? default yes, but might be altered below )
	s" loader_menu_frame" getenv dup -1 = if ( 1 )
		drop \ no custom frame type
	else ( 1 )  2dup s" single" compare-insensitive 0= if ( 2 )
		f_single ( see frames.4th )
	else ( 2 )  2dup s" double" compare-insensitive 0= if ( 3 )
		f_double ( see frames.4th )
	else ( 3 ) s" none" compare-insensitive 0= if ( 4 )
		drop FALSE \ don't draw a box
	( 4 ) then ( 3 ) then ( 2 )  then ( 1 ) then
	if
		42 13 menuX @ 3 - menuY @ 1- box \ Draw frame (w,h,x,y)
	then
;

\ This function initializes the menu. Call this from your `loader.rc' file
\ before calling any other menu-related functions.
\
: menu-init ( -- )
	menu_start
	1- menuidx !    \ Initialize the starting index for the menu
	0 menurow !     \ Initialize the starting position for the menu

	\ Assign configuration values
	s" loader_menu_y" getenv dup -1 = if
		drop \ no custom row position
		menu_default_y
	else
		\ make sure custom position is a number
		?number 0= if
			menu_default_y \ or use default
		then
	then
	menuY !
	s" loader_menu_x" getenv dup -1 = if
		drop \ no custom column position
		menu_default_x
	else
		\ make sure custom position is a number
		?number 0= if
			menu_default_x \ or use default
		then
	then
	menuX !

	['] menu-box console-iterate
	at-bl
;

also menu-namespace

\ Main function. Call this from your `loader.rc' file.
\
: menu-display ( -- )

	0 menu_timeout_enabled ! \ start with automatic timeout disabled

	\ check indication that automatic execution after delay is requested
	s" menu_timeout_command" getenv -1 <> if ( Addr C -1 -- | Addr )
		drop ( just testing existence right now: Addr -- )

		\ initialize state variables
		seconds menu_time ! ( store the time we started )
		1 menu_timeout_enabled ! ( enable automatic timeout )

		\ read custom time-duration (if set)
		s" autoboot_delay" getenv dup -1 = if
			drop \ no custom duration (remove dup'd bunk -1)
			menu_timeout_default \ use default setting
		else
			2dup ?number 0= if ( if not a number )
				\ disable timeout if "NO", else use default
				s" NO" compare-insensitive 0= if
					0 menu_timeout_enabled !
					0 ( assigned to menu_timeout below )
				else
					menu_timeout_default
				then
			else
				-rot 2drop

				\ boot immediately if less than zero
				dup 0< if
					drop
					menu-create
					at-bl
					0 boot
				then
			then
		then
		menu_timeout ! ( store value on stack from above )

		menu_timeout_enabled @ 1 = if
			\ read custom column position (if set)
			s" loader_menu_timeout_x" getenv dup -1 = if
				drop \ no custom column position
				menu_timeout_default_x \ use default setting
			else
				\ make sure custom position is a number
				?number 0= if
					menu_timeout_default_x \ or use default
				then
			then
			menu_timeout_x ! ( store value on stack from above )

			\ read custom row position (if set)
			s" loader_menu_timeout_y" getenv dup -1 = if
				drop \ no custom row position
				menu_timeout_default_y \ use default setting
			else
				\ make sure custom position is a number
				?number 0= if
					menu_timeout_default_y \ or use default
				then
			then
			menu_timeout_y ! ( store value on stack from above )
		then
	then

	menu-create

	begin \ Loop forever

		at-bl
		getkey     \ Block here, waiting for a key to be pressed

		dup -1 = if
			drop exit \ Caught abort (abnormal return)
		then

		\ Boot if the user pressed Enter/Ctrl-M (13) or
		\ Ctrl-Enter/Ctrl-J (10)
		dup over 13 = swap 10 = or if
			drop ( no longer needed )
			s" boot" evaluate
			exit ( pedantic; never reached )
		then

		dup menureboot @ = if 0 reboot then

		\ Evaluate the decimal ASCII value against known menu item
		\ key associations and act accordingly

		49 \ Iterator start (loop range 49 to 56; ASCII '1' to '8')
		begin
			dup menukeyN @
			rot tuck = if

				\ Adjust for missing ACPI menuitem on non-i386
\				arch-i386? true <> menuacpi @ 0<> and if
\					menuacpi @ over 2dup < -rot = or
\					over 58 < and if
\					( key >= menuacpi && key < 58: N -- N )
\						1+
\					then
\				then

				\ Test for the environment variable
				dup menu_command[x]
				getenv dup -1 <> if
					\ Execute the stored procedure
					evaluate

					\ We expect there to be a non-zero
					\  value left on the stack after
					\ executing the stored procedure.
					\ If so, continue to run, else exit.

					0= if
						drop \ key pressed
						drop \ loop iterator
						exit
					else
						swap \ need iterator on top
					then
				then

				\ Re-adjust for missing ACPI menuitem
\				arch-i386? true <> menuacpi @ 0<> and if
\					swap
\					menuacpi @ 1+ over 2dup < -rot = or
\					over 59 < and if
\						1-
\					then
\					swap
\				then
			else
				swap \ need iterator on top
			then

			\
			\ Check for menu keycode shortcut(s)
			\
			dup menu_keycode[x]
			getenv dup -1 = if
				drop
			else
				?number 0<> if
					rot tuck = if
						swap
						dup menu_command[x]
						getenv dup -1 <> if
							evaluate
							0= if
								2drop
								exit
							then
						else
							drop
						then
					else
						swap
					then
				then
			then

			1+ dup 56 > \ increment iterator
			            \ continue if less than 57
		until
		drop \ loop iterator
		drop \ key pressed

	again	\ Non-operational key was pressed; repeat
;

\ This function unsets all the possible environment variables associated with
\ creating the interactive menu.
\
: menu-unset ( -- )

	49 \ Iterator start (loop range 49 to 56; ASCII '1' to '8')
	begin
		dup menu_init[x]    unsetenv	\ menu initializer
		dup menu_command[x] unsetenv	\ menu command
		dup menu_caption[x] unsetenv	\ menu caption
		dup ansi_caption[x] unsetenv	\ ANSI caption
		dup menu_keycode[x] unsetenv	\ menu keycode
		dup toggled_text[x] unsetenv	\ toggle_menuitem caption
		dup toggled_ansi[x] unsetenv	\ toggle_menuitem ANSI caption

		48 \ Iterator start (inner range 48 to 57; ASCII '0' to '9')
		begin
			\ cycle_menuitem caption and ANSI caption
			2dup menu_caption[x][y] unsetenv
			2dup ansi_caption[x][y] unsetenv
			1+ dup 57 >
		until
		drop \ inner iterator

		0 over menukeyN      !	\ used by menu-create, menu-display
		0 over init_stateN   !	\ used by menu-create
		0 over toggle_stateN !	\ used by toggle_menuitem
		0 over init_textN   c!	\ used by toggle_menuitem
		0 over cycle_stateN  !	\ used by cycle_menuitem

		1+ dup 56 >	\ increment, continue if less than 57
	until
	drop \ iterator

	s" menu_timeout_command" unsetenv	\ menu timeout command
	s" menu_reboot"          unsetenv	\ Reboot menu option flag
	s" menu_acpi"            unsetenv	\ ACPI menu option flag
	s" menu_kmdb"            unsetenv	\ kmdb menu option flag
	s" menu_osconsole"       unsetenv	\ osconsole menu option flag
	s" menu_options"         unsetenv	\ Options separator flag
	s" menu_optionstext"     unsetenv	\ separator display text
	s" menu_init"            unsetenv	\ menu initializer

	0 menureboot !
	0 menuacpi !
	0 menukmdb !
	0 menuosconsole !
	0 menuoptions !
;

only forth definitions also menu-infrastructure

\ This function both unsets menu variables and visually erases the menu area
\ in-preparation for another menu.
\
: menu-clear ( -- )
	menu-unset
	menu-erase
;

bullet menubllt !

also menu-namespace

\ Initialize our menu initialization state variables
0 init_state1 !
0 init_state2 !
0 init_state3 !
0 init_state4 !
0 init_state5 !
0 init_state6 !
0 init_state7 !
0 init_state8 !

\ Initialize our boolean state variables
0 toggle_state1 !
0 toggle_state2 !
0 toggle_state3 !
0 toggle_state4 !
0 toggle_state5 !
0 toggle_state6 !
0 toggle_state7 !
0 toggle_state8 !

\ Initialize our array state variables
0 cycle_state1 !
0 cycle_state2 !
0 cycle_state3 !
0 cycle_state4 !
0 cycle_state5 !
0 cycle_state6 !
0 cycle_state7 !
0 cycle_state8 !

\ Initialize string containers
0 init_text1 c!
0 init_text2 c!
0 init_text3 c!
0 init_text4 c!
0 init_text5 c!
0 init_text6 c!
0 init_text7 c!
0 init_text8 c!

only forth definitions
