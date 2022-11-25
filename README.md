
Mojolicious lite and bootstrap based simple cms

  ### Features
  ```
  - multi-users micro cms system
  - broacast messages to the home page 
  - message page allocation 
  - multiple HTML pages ( ACL restricted )
  - interpred content code by using eval 
  ```
  e.g Add message and assign item to page 
  ```shell
  eval use Mojo::UserAgent; my $ua  = Mojo::UserAgent->new; my $res = $ua->get('docs.mojolicious.org')->result; print $res->code;
  ```
  ### Usage
  
  - generate a company intern micro monitoring tool
  - generate a company intern html bookmarks list 
  
  ### Requirements
  ```
	- perl 5.10 to higher
	- Mojolicious (4.62, Top Hat)
  ```
  #### Install
  ```
	-  $ curl -L https://cpanmin.us | perl - --sudo App::cpanminus.
	-  $ cpanm ORLite.pm
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
