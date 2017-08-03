
Mojolicious lite and bootstrap based simple cms

  ### Feutures
  ```
	- 2 factors authentication ( google authenticator + token or local database )
	- broacast messages 
	- multiple HTML pages ( ACL restricted )
  ```
  ### Requirements
  ```
	- perl 5.10 to higher
	- Mojolicious (4.62, Top Hat)
  ```
  #### Install
  ```
	-  $ curl -L https://cpanmin.us | perl - --sudo App::cpanminus.
	-  $ cpanm ORLite.pm
	-  $ cpanm Auth::GoogleAuth;
	-  $ cpanm Mojolicious
	-  $ git clone https://github.com/ovntatar/MicroCMS.git
	-  $ cd MicroCMS
	-  $ morbo MicroCMS.pl
```
  ### Login

    #### Super Admin:
```
    - access:	http://127.0.0.1:3000
    - email: 	admin@myproject.com
    - password:	admin
```
    #### Another account( normal user ):
```
    - email: bal@bal.com
    - password: bal
```
