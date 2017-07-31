#!/usr/bin/env perl

package Model;

use ORLite {
    file    => 'MicroCMS.db',
    cleanup => 'VACUUM',
    create  => sub {
        my $dbh = shift;
        $dbh->do(
            'CREATE TABLE user 
				(email   TEXT NOT NULL UNIQUE PRIMARY KEY,
				password TEXT NOT NULL,
                fac_auth TEXT NOT NULL DEFAULT "NO",
				token TEXT,
				rule     TEXT);'
        );
        $dbh->do(
            'CREATE TABLE entries 
				(id INTEGER NOT NULL PRIMARY KEY
				ASC AUTOINCREMENT, 
				email TEXT NOT NULL, 
				content TEXT NOT NULL, 
				date TEXT NOT NULL);'
        );

        $dbh->do(
            'CREATE TABLE page
            ( id INTEGER NOT NULL PRIMARY KEY ASC AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            user_email TEXT NOT NULL,
            created_at TEXT NOT NULL,
            can_show INTEGER NOT NULL DEFAULT 0); '
        );

        $dbh->do(
            'INSERT INTO user 
				(email, password, fac_auth, token, rule) 
				VALUES("admin@myproject.com","21232f297a57a5a743894a0e4a801fc3", "NO", "","3");'
        );

        $dbh->do(
            'INSERT INTO page 
				(title, content, user_email, created_at, can_show ) 
				VALUES("Test", "Can be a long long long text content here", "admin@myproject.com", "2017-07-30 18:20", 1 );'
        );
    },
};

sub get_users {
    return Model->selectall_arrayref( 'SELECT * from user', { Slice => {} }, );
}

sub get_user {
    return Model->selectrow_hashref( 'SELECT * from user where email = ?', { Slice => {} }, $_[0] );
}

sub update_user {
    my $data = shift;
    my $user = Model::get_user( $data->{email} );
    return unless $user;

    Model->do( 'UPDATE user SET password = ?, fac_auth = ?, token = ?, rule = ? WHERE email = ?', {}, $data->{password}, $data->{fac_auth}, $data->{token}, $data->{rule}, $data->{email} );
}

sub get_messages {
    return Model->selectall_arrayref( 'SELECT * from entries', { Slice => {} } );
}

sub get_pages {
    return Model->selectall_arrayref( 'SELECT * from page', { Slice => {} }, );
}

sub get_pages_can_show {
    my $pages = Model->selectall_arrayref( 'SELECT id, title FROM page WHERE can_show = ?', undef, 1 );
    my @return;
    map { push @return, { id => $_->[0], title => $_->[1] } } @$pages;
    return \@return;
}

sub get_page {
    return Model->selectrow_hashref( 'SELECT * from page WHERE id = ?', { Slice => {} }, $_[0] );
}

sub update_page {
    my $data = shift;
    my $page = Model::get_page( $data->{id} );
    return unless $page;

    Model->do( 'UPDATE page SET title = ?, content = ?, user_email = ?, created_at = ?, can_show = ?  WHERE  id = ?', {}, $data->{title}, $data->{content}, $data->{user_email}, $data->{created_at}, $data->{can_show}, $data->{id} );
}

sub create_page {
    my $data = shift;

    Model->do( 'INSERT INTO page (title, content, user_email, created_at, can_show ) VALUES (?, ?, ?, ?, ? )', {}, $data->{title}, $data->{content}, $data->{user_email}, $data->{created_at}, $data->{can_show} );
}

sub delete_page {
    my $id = shift;
    return unless $id;
    Model->do( 'DELETE FROM page WHERE id = ?', {}, $id );
}

package main;

use Mojolicious::Lite;
use Mojo::ByteStream 'b';
use Mojo::Date;
use Auth::GoogleAuth;
use Data::Dumper;

# enable option if you using 4.90 or older version
#app->secret('MicroCMS791'); # Removed deprecated secret after version 4.91

helper do_auth_login_fail => sub {
    my ( $self, $user ) = @_;
    $self->flash( user           => $user );
    $self->flash( failed_message => 'Wrong auth codes!' );
    return $self->redirect_to('/login/auth');
};

helper do_login_success => sub {
    my ( $self, $user ) = @_;
    return 0 unless $user;
    $self->session( rule  => $user->{rule} );
    $self->session( email => $user->{email} );
    return 1;
};

helper auth => sub {
    my $self     = shift;
    my $email    = $self->param('email');
    my $password = b( $self->param('password') )->md5_sum;
    if ( Model::User->count( 'WHERE email=? AND password=?', $email, $password ) == 1 ) {
        my $user = Model::get_user($email);
        return unless $user;
        if ( $user->{token} && length( $user->{token} ) > 1 ) {
            $self->session( user => $user );
            $self->flash( sucess_message => 'Need Google Authenticator TBOT Abstractio' );
            $self->redirect_to('/login/auth');
            return 0;
        }
        else {
            return $self->do_login_success($user);
        }
    }
    else {
        $self->flash( failed_message => 'Wrong email or password!' );
        $self->redirect_to('/');
        return;
    }
};

helper check_token => sub {
    my $self       = shift;
    my $validation = $self->validation;
    return $self->render( text => 'Bad CSRF token!', status => 403 )
        if $validation->csrf_protect->has_error('csrf_token');
};

hook before_render => sub {
    my $self = shift;

    my $pages = Model::get_pages_can_show();
    $self->stash( nav_pages => $pages );
};

get '/' => sub {
    my $self    = shift;
    my $mesages = Model::get_messages();
    $self->stash( mesages => $mesages );
} => 'index';

get '/help' => 'help';

get '/logout' => sub {
    my $self = shift;
    $self->session( expires => 1 );
    $self->redirect_to('/');
};

get '/page/*id' => sub {
    my $self = shift;
    my $id   = $self->stash('id');
    my $page = Model::get_page($id);
    $self->stash( page => $page );
} => 'page';

get '/login/auth'  => 'auth';
post '/login/auth' => sub {
    my $self = shift;
    return $self->redirect_to('/login/auth') if $self->check_token;
    my $user = $self->session('user');
    return $self->redirect_to('/') unless $user;
    my $codes = $self->param('codes');

    $self->do_auth_fail($user) unless $codes;

    my $auth = Auth::GoogleAuth->new;
    $auth = Auth::GoogleAuth->new(
        {   secret32 => $user->{token},
            key_id   => $user->{email},
        }
    );

    $self->do_auth_login_fail($user) if $auth->verify($codes) == 0;
    return $self->redirect_to('/')   if $self->do_login_success($user);
};

post '/login' => sub {
    my $self = shift;
    return if $self->check_token;
    return unless $self->auth;
    $self->flash( sucess_message => 'Wellcome!' );
    $self->redirect_to('/');
};

under sub {
    my $self = shift;
    return 1 if $self->session("email");
    $self->flash( failed_message => 'Access Denied!' );
    $self->redirect_to('/');
};

get '/message' => sub {
    my $self    = shift;
    my $mesages = Model::get_messages();
    $self->stash( mesages => $mesages );
} => 'message';

get '/message/addmessage' => sub {
    my $self = shift;
    my $date = Mojo::Date->new(time);
    $self->stash( date => $date );
} => 'addmessage';

post '/message/addmessage' => sub {
    my $self = shift;
    return if $self->check_token;

    Model::Entries->create(
        email   => $self->param('email'),
        content => $self->param('message'),
        date    => $self->param('date'),
    );
    $self->flash( sucess_message => 'Create message sucessfull!' );
    $self->redirect_to('/message');
};

post '/message/delete/*id' => => sub {
    my $self = shift;
    return if $self->check_token;
    my $id = $self->stash('id');
    Model::Entries->delete_where( 'id=?', $id );
    my $mesages = Model::get_messages();
    $self->stash( mesages => $mesages );
    $self->flash( sucess_message => "Message sucessfull deleted!" );
    $self->redirect_to('/message');
};

under sub {
    my $self = shift;
    return 1 if $self->session("rule") == 3;
    $self->flash( failed_message => 'Permission denied!' );
    return $self->redirect_to( '/' );
};

get '/admin/users' => sub {
    my $self  = shift;
    my $users = Model::get_users();
    $self->stash( users => $users );
};
get '/admin/user/edit/*email' => sub {
    my $self  = shift;
    my $email = $self->stash('email');
    my $user  = Model::get_user($email);
    unless ($user) {
        $self->flash( failed_message => sprintf 'User: %s not found', $email );
        return $self->redirect_to('/admin/users');
    }
    $self->stash( user => $user );
} => 'edituser';

post '/admin/user/edit/*email_org' => sub {
    my $self      = shift;
    my $email_org = $self->param('email_org');
    my $email     = $self->param('email');
    return $self->redirect_to('/admin/users') unless $email_org eq $email;

    my $user = Model::get_user($email);
    unless ($user) {
        $self->flash( failed_message => 'User not found' );
        return $self->redirect_to('/admin/users');
    }

    my $password = b( $self->param('password') )->md5_sum, my $rule = $self->param('rule'), my $fac_auth = $self->param('fac_auth');
    my $token = $self->param('token');
    if ( lc($fac_auth) eq 'YES' and not $token ) {
        $self->falsh( failed_message => 'No token set' );
        $self->stash( user => $user );
        return $self->redirect_to("/admin/user/edit/$email");
    }

    Model::update_user(
        {   email    => $email,
            password => $password,
            rule     => $rule,
            fac_auth => $fac_auth,
            token    => $token,
        }
    );
    return $self->redirect_to('/admin/users');
};

get '/admin/user/get_token' => sub {
    my $self  = shift;
    my $auth  = Auth::GoogleAuth->new;
    my $token = $auth->generate_secret32;
    $self->render( text => $token );
} => 'get_token';

get '/admin/adduser' => sub {
    shift->stash( user => {});
} => 'adduser';

post '/admin/delete/*email' => => sub {
    my $self = shift;
    return if $self->check_token;
    my $email = $self->stash('email');
    Model::User->delete_where( 'email=?', $email );
    my $users = Model::get_users();
    $self->stash( users => $users );
    $self->flash( sucess_message => "User with the mail $email sucessfull deleted!" );
    $self->redirect_to('/admin/users');
};

post '/admin/adduser' => sub {
    my $self = shift;
    return if $self->check_token;

    if ( Model::User->count( 'WHERE email=?', $self->param('email') ) == 1 ) {
        $self->flash( failed_message => 'Duplicate email found! Can not create user!' );
        $self->redirect_to('/admin/users');
        return;
    }
    Model::User->create(
        email    => $self->param('email'),
        password => b( $self->param('password') )->md5_sum,
        fac_auth => $self->param( 'fac_auth' ) || 'NO',
        token => $self->param( 'token' ) || '',
        rule     => $self->param('rule'),
    );
    $self->flash( sucess_message => 'Create user sucessfull!' );
    $self->redirect_to('/admin/users');
};

get '/admin/pages' => sub {
    my $self  = shift;
    my $pages = Model::get_pages();
    $self->stash( pages => $pages );
} => 'pages';

any ['get', 'post'] => '/admin/page/create' => sub {
    my $self = shift;

    if ( lc( $self->req->method ) eq 'get' ) {
        $self->stash( page => {} );
    }
    else {
        my $title      = $self->param('title');
        my $content    = $self->param('content');
        my $user_email = $self->param('user_email');
        my $can_show   = $self->param('can_show') || 0;
        my $created_at = $self->param('created_at');

        unless ($title) {
            $self->flash( failed_message => 'Title must input' );
            return $self->redirect_to('/admin/page/create');
        }

        Model::create_page(
            {   title      => $title,
                content    => $content,
                user_email => $user_email,
                created_at => $created_at,
                can_show   => $can_show,
            }
        );

        $self->flash( sucess_message => 'Create page success' );
        return $self->redirect_to('/admin/pages');
    }
} => 'page_create';

any ['get', 'post'] => '/admin/page/edit/*id' => sub {
    my $self = shift;
    my $id   = $self->stash('id');
    my $page = Model::get_page($id);

    unless ($page) {
        $self->flash( failed_message => 'Page Not found' );
        return $self->redirect_to('/admin/pages');
    }
    if ( lc( $self->req->method ) eq 'post' ) {

        # did update page thins
        my $title      = $self->param('title');
        my $content    = $self->param('content');
        my $user_email = $self->param('user_email');
        my $can_show   = $self->param('can_show') || 0;
        my $created_at = $self->param('created_at');

        unless ($title) {
            $self->flash( failed_message => 'Title must input' );
            return $self->redirect_to("/admin/page/edit/$id");
        }

        Model::update_page(
            {   id         => $id,
                title      => $title,
                content    => $content,
                user_email => $user_email,
                created_at => $created_at,
                can_show   => $can_show,
            }
        );

        $self->flash( sucess_message => 'Edit page success' );
        return $self->redirect_to('/admin/pages');
    }
    $self->stash( page => $page );
} => 'page_edit';

get '/admin/page/delete/*id' => sub {
    my $self = shift;
    my $id   = $self->stash('id');
    $self->flash( failed_message => 'page not found' ) unless $id;

    Model::delete_page($id);

    $self->flash( sucess_message => 'page not found' ) unless $id;
    return $self->redirect_to('/admin/pages');
} => 'page_delete';

app->start;

__DATA__
@@ layouts/default.html.ep

<!DOCTYPE html>
<html lang="en">
%= t header => begin
  %= t meta => charset => 'utf-8'
  %= t meta => name => 'viewport'  => content=>'width=device-width, initial-scale=1.0'
  %= t meta => name => 'description' => content=>''
  %= t meta => name=> 'author' => content=>''
%end
%= stylesheet '//netdna.bootstrapcdn.com/bootstrap/3.0.3/css/bootstrap.min.css'
%= javascript '//ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js'
%= stylesheet begin
body {
  padding-top: 50px;
  padding-bottom: 20px;
}
%end

<body>
%= t div => class => 'navbar navbar-inverse navbar-fixed-top' => role =>'navigation' => begin
  %= t div => class => 'container' => begin
    %= t div => class => 'navbar-header test111' => begin
	    %= t button => type=>'button' => class=> 'navbar-toggle' => 'data-toggle' => 'collapse' => 'data-target' => '.navbar-collapse' => begin
	      %= t span => class => 'sr-only' => 'Toggle navigation'
	      %= t span => class => 'icon-bar'
      %end

      %= link_to 'MicroCMS' => '/' => class => 'navbar-brand'
	    %= link_to 'Help' => '/help' => class => 'navbar-brand'
    %end
  
    %= t div => class => 'navbar-collapse collapse' => begin	  
  	  % if (!session 'email') {
  	    %= form_for '/login' => (method => 'post') => class =>'navbar-form navbar-right' => role => 'form'=> begin 
  	      %= csrf_field
  	      %= t div => class => 'form-group' => begin
  		      %= text_field 'email', name => 'email', class => 'form-control', placeholder =>'email'
  	      %end
  	      %= t div => class => 'form-group' => begin
  		      %= password_field 'password', name => 'password', class => 'form-control', placeholder =>'password'
  	      %end 
          %= submit_button 'Login', class => 'btn btn-success'
        %end
  	 % } else {
        %= t ul => class => 'nav navbar-nav' => begin
  	      % current_route eq 'index' ?  $self->stash( class => 'active') :  $self->stash( class => '');
  		    <li class="<%= stash 'class' %>" ><a href="/">Home</a></li>
  
          % if ( (session 'rule') > 2 ) {
  	        % current_route eq 'adminusers' ? $self->stash( class => 'active') : $self->stash( class => '');
  		      <li class="<%= stash 'class' %>" ><a href="/admin/users">Admin</a></li>
  	      %}
  	  
          % current_route eq 'message' ? $self->stash( class => 'active') : $self->stash( class => '');
  		    <li class="<%= stash 'class' %>" ><a href="/message">Message</a></li>
          
          %= t li => begin
            %= link_to 'Pages' => '/admin/pages'
          % end

          % foreach my $page ( @$nav_pages ) {
            %= t li => begin
              %= link_to "$page->{title}" => "/page/$page->{id}"
            % end
          % }
        %end
  		
        %= form_for '/logout' => method => 'get' => class =>'navbar-form navbar-right' => begin
          % my $text = 'Logout ' . session 'email'; 
          %= submit_button $text => class => 'btn btn-success'
  		  %end
  	 %}
    %end
  %end
%end


%= t div => class => 'container' => begin
  % if ( flash 'failed_message' || stash 'failed_message' ) {
  %= t div => class=> 'alert alert-danger' => begin
	  %= flash 'failed_message'
	  %= stash 'failed_message'
  %end
  %}

  % if ( flash 'sucess_message' || flash 'sucess_message' ) {
  %= t div => class=>'alert alert-success' => begin
	  %= flash 'sucess_message'
	  %= stash 'sucess_message'
  %end
  %}
  
  %= t div => class => '' => style => 'margin-top: 20px' => content 
%end

%= stylesheet begin
.footer {
  bottom: 0;
  width: 100%;
  background-color: #000000;
  height: 50px;
% end

%= t footer => id => 'footer' => class => 'footer navbar-fixed-bottom' => begin
  %= t div => class => 'container' => begin
    <br>
    %= t p => class => 'text-muted' => begin
      © 2017
      %= link_to 'Project GitHub' => 'https://github.com/ovntatar/MicroCMS'
    %end
  %end
%end

%= javascript '//netdna.bootstrapcdn.com/bootstrap/3.3.0/js/bootstrap.min.js'
</body>
</html>



@@ index.html.ep
% layout 'default';

%= t h1 => 'MicroCMS'

For demo please use the following details:<br>
Email <b>admin@myproject.com</b>, Password: <b>admin</b><br>
%= stash 'pw'
<hr>

%= t div => class => 'panel panel-default' => begin
  %= t div => class => 'panel-heading' => 'Message - title'
  %= t div => class => 'panel-body' => begin
    %= t ul => begin
      % for my $item (@$mesages) {
        % my $item_str = sprintf( '%s - %s', $item->{content}, $item->{email} );
	      %= t li => begin
          %= $item_str
        % end
	    %} 
    % end
  % end
% end


@@ adminusers.html.ep
% layout 'default';

%= link_to 'Add new user' => 'adduser' => class => 'btn btn-sm btn-primary'

<hr>

%= t table => class => 'table table-striped' => begin
  %= t thead => begin
	  %= t tr => begin
	  %= t th => 'Email'
      %= t th => 'Password'
      %= t th => '2FacAuth'
      %= t th => 'Token'
	  %= t th => 'Rule'
	  %= t th => 'Action'
    % end
  % end

  %= t tbody => begin
  	% for my $items (@$users) {
  	  %= t tr => begin
  	    %= t td => $items->{email}
  	    %= t td => $items->{password}
  	    %= t td => begin
            % if ( lc( $items->{fac_auth} ) eq 'yes' ){
                %= t span => class => 'label label-success' => 'Enable'
            % } else {
                %= t span => class => 'label label-default' => 'Disable'
            % }
        % end
  	    %= t td => $items->{token}
  	    %= t td => $items->{rule}
        %= t td => begin
  	      %= link_to 'Edit' => "/admin/user/edit/$items->{email}" => class => 'btn btn-warning btn-sm' 
          %= form_for "delete/$items->{email}" => (method => 'post') => begin
  	        %= csrf_field
  	        %= submit_button 'Delete' => class => 'btn btn-primary btn-sm'
  	      %end 
        % end
      % end
  	%}
  % end
% end


@@ edituser.html.ep
% layout 'default';

%= t h3 => 'Edit User'
<hr>
%= form_for "/admin/user/edit/$user->{email}" => method => 'post' => class =>'form-horizontal' => role => 'form'=> begin
%= include '_user_form'

%= t div => class => 'form-group' => begin 
    %= t div => class => 'col-sm-offset-2 col-sm-10' => begin
      %= submit_button 'Update' => class => 'btn btn-default btn-primary'
  % end
% end

%end


@@ message.html.ep
% layout 'default';

%= link_to 'Add new message' => '/message/addmessage' => class => 'btn btn-primary btn-sm'
<hr>

% if ( $mesages ) {
%= t table => class => 'table table-striped' => begin
  %= t thead => begin
	  %= t tr => begin
	    %= t th => 'email'
	    %= t th => 'content'
	    %= t th => 'date'
	    %= t th => 'Action'
    % end
  % end
  
  %= t tbody => begin
	  % for my $item (@$mesages) {
	    %= t tr => begin
	      %= t td => $item->{email}
	      %= t td => $item->{content}
	      %= t td => $item->{date}
	      %= t td => begin
	        %= form_for "/message/delete/$item->{id}" => method => 'post' => begin
	          %= csrf_field
              % if ( session->{rule} < 3 ){
                %= submit_button 'Delete' => class => 'btn btn-primary btn-sm' => disabled => 'disabled'
              % } else {
                %= submit_button 'Delete' => class => 'btn btn-primary btn-sm'
              % }
          % end
	      % end 
	    % end 
	  %}
	% end 
% end
% }

@@ adduser.html.ep
% layout 'default';

%= t h3 => 'Add User'
<hr>
%= form_for '/admin/adduser' => method => 'post' => class =>'form-horizontal' => role => 'form'=> begin
%= include '_user_form'

%= t div => class => 'form-group' => begin 
    %= t div => class => 'col-sm-offset-2 col-sm-10' => begin
      %= submit_button 'Add User' => class => 'btn btn-default'
  % end
% end
%end


@@ _user_form.html.ep
%= csrf_field
%= t div => class => 'form-group' => begin
    %= label_for 'inputEmail3' => 'Email' => class => 'col-sm-2 control-label'
    %= t div => class => 'col-sm-10' => begin
      %= input_tag 'email', type => 'email', class => 'form-control', id => 'inputEmail3',  placeholder => 'Email', value => "$user->{email}"
  % end
% end

%= t div => class => 'form-group' => begin
    %= label_for 'inputPassword3' => 'Password' => class => 'col-sm-2 control-label'
    %= t div => class => 'col-sm-10' => begin
      %= input_tag 'password', type => 'password', class => 'form-control', id => 'inputPassword3', placeholder => 'Password', value => "$user->{password}"
  % end
% end

%= t div => class => 'form-group' => begin
    %= label_for 'token_flag' => '2FacAuth' => class => 'col-sm-2 control-label'
    %= t div => class => 'col-sm-10' => begin
      % if ( $user->{fac_auth} eq 'YES' ) {
        %= radio_button fac_auth => 'YES', checked => 1
      % } else {
        %= radio_button fac_auth => 'YES', 
      % }
      Enable

      % if ( $user->{fac_auth} eq 'NO' ) {
        %= radio_button fac_auth => 'NO', checked => 1
      % } else {
        %= radio_button fac_auth => 'NO'
      % }
      Disable
  % end
% end

%= t div => class => 'form-group' => begin
    %= label_for 'inputtoken' => 'Token' => class => 'col-sm-2 control-label'
    %= t div => class => 'col-sm-10' => begin
      %= input_tag 'token', type => 'text', class => 'form-control', id => 'inputtoken', placeholder => 'token', value => "$user->{token}"
  % end
% end


%= t div => class => 'form-group' => begin
    %= label_for 'inputNumber' => 'Rule' => class => 'col-sm-2 control-label'
    %= t div => class => 'col-sm-10' => begin
      %= input_tag 'rule', type => 'number', class => 'form-control', id => 'inputNumber', placeholder => 'Rule', value => "$user->{rule}"
  % end
% end

%= javascript begin
$('document').ready( function() {
    $("input[name='fac_auth']").click( function(){
        if ( this.value == 'NO' ) {
            $("#inputtoken").val('');
        } else {
            var email = $("input[name='email']").val();
            $.ajax( {
                url: '/admin/user/get_token',
                success: function(token) {
                    $("#inputtoken").val( token );
                },
                error: function() {
                    alert( 'Get new 2FacAuth token fail!' );
                }
            })
        }
    });
});
% end

@@ addmessage.html.ep
% layout 'default';

%= t h3 => 'Add Message'

%= form_for '/message/addmessage' => method => 'post' => class =>'form-horizontal' => role => 'form'=> begin
  %= csrf_field
  %= t div => class => "form-group" => begin
	  %= label_for 'inputEmail3' => 'Email' => class => 'col-sm-2 control-label'
	  %= t div => class => 'col-sm-10' => begin
      %= input_tag 'email' => session->{email}, type => 'email', class => 'form-control', id => 'inputEmail3', placeholder => 'Email'
    % end
  % end

  %= t div => class => 'form-group' => begin
	  %= label_for 'inputTxt' => 'Message' => class => 'col-sm-2 control-label'
	  %= t div => class => 'col-sm-10' => begin
	    %= input_tag 'message', type => 'text', class => 'form-control', id => 'inputTxt', placeholder => 'Message'
    % end
  % end
	
  %= t div => class=> 'form-group' => begin
	  %= label_for 'inputDatetime' => 'Datetime' => class => 'col-sm-2 control-label'
	  %= t div => class => 'col-sm-10' => begin
	    %= input_tag 'date' => stash->{date}, type => "text",  class => 'form-control', id => 'inputDatetime', placeholder => 'Datetime'
    % end
  % end

  %= t div => class => 'form-group' => begin
	  %= t div => class => 'col-sm-offset-2 col-sm-10' => begin
      %= submit_button 'Add Message' => class => 'btn btn-default'
    % end
  % end 
%end

@@ help.html.ep
% layout 'default';

%= t h3 => 'Help'

%= t p => 'Mojolicious lite and bootstrap based simple cms'
<b>Requirements</b>
<ul>
  <li>perl 5.10 to higher
  <li>Mojolicious (4.62, Top Hat)
</ul>

<b>Install & Start dev Server</b>
<ul>
  <li>$ curl -L https://cpanmin.us | perl - --sudo App::cpanminus.</li>
  <li>$ cpanm ORLite.pm</li>
  <li>$ cpanm Mojolicious</li>
  <li>$ git clone https://github.com/ovntatar/MicroCMS.git</li>
  <li>$ cd MicroCMS</li>
  <li>$ morbo MicroCMS.pl</li>
</ul>

@@ auth.html.ep
% layout 'default';

%= t h3 => 'Google Authenticator'
<hr>
%= form_for '/login/auth' => method => 'post' => class =>'form-horizontal' => role => 'form'=> begin
  %= csrf_field
  %= t div => class => "form-group" => begin
	  %= label_for 'g_codes' => 'Codes' => class => 'col-sm-2 control-label'
	  %= t div => class => 'col-sm-2' => begin
      %= input_tag 'codes', type => 'number', class => 'form-control', id => 'g_codes', placeholder => 'Codes'
    % end
  % end

  %= t div => class => 'form-group' => begin
	  %= t div => class => 'col-sm-offset-2 col-sm-2' => begin
      %= submit_button 'Auth' => class => 'btn btn-default btn-success'
    % end
  % end 
%end

@@ pages.html.ep
% layout 'default';

%= t h3 => 'Pages List'
%= link_to 'Create Page' => '/admin/page/create' => class => 'btn btn-primary'
<hr>
% if ( @$pages > 0 ) {
%= t table => class => 'table table-hover table-condensed' => begin
  %= t thead => begin
    %= t tr => begin
      %= t th => 'Title'
      %= t th => 'Content'
      %= t th => 'Author'
      %= t th => 'Date'
      %= t th => 'ShowNav'
      %= t th => 'Action'
    % end
  % end

  %= t tbody => begin
    % foreach my $page ( @$pages ) {
      %= t tr => begin
        %= t td => $page->{title}
        %= t td => $page->{content}
        %= t td => $page->{user_email}
        %= t td => $page->{created_at}
        %= t td => begin 
            % if ( $page->{can_show} && $page->{can_show} == 1 ) {
                %= t span => class => 'label label-success' => 'YES'
            % } else {
                %= t span => class => 'label label-default' => 'NO'
            %}
        % end
        %= t td => begin 
            %= link_to 'Edit' => "/admin/page/edit/$page->{id}" => class => 'btn btn-xs btn-primary'
            %= link_to 'Delete' => "/admin/page/delete/$page->{id}" => class => 'btn btn-xs btn-danger'
        % end
      % end
    % }
  % end
% end
% } else {
  %= t div => class => 'alert alert-warning' => 'No pages data!'
% }


@@ page_create.html.ep
% layout 'default';

%= t h3 => 'Create Page'
<hr>
%= form_for '/admin/page/create' => method => 'post' => class =>'form-horizontal' => role => 'form'=> begin
    %= include '_page_form'
    %= t div => class => 'form-group' => begin 
        %= t div => class => 'col-sm-offset-2 col-sm-10' => begin
            %= submit_button 'Create Page' => class => 'btn btn-primary'
        % end
    % end
% end

@@ page_edit.html.ep
% layout 'default';

%= t h3 => 'Edit Page'
<hr>
%= form_for "/admin/page/edit/1" => method => 'post' => class =>'form-horizontal' => role => 'form'=> begin
    %= include '_page_form'
    
    %= t div => class => 'form-group' => begin 
        %= t div => class => 'col-sm-offset-2 col-sm-10' => begin
            %= submit_button 'Edit Page' => class => 'btn btn-primary'
        % end
    % end
% end


@@ _page_form.html.ep 
%= csrf_field
%= t div => class => 'form-group' => begin
    %= label_for 'input_title' => 'Title' => class => 'col-sm-2 control-label'
    %= t div => class => 'col-sm-10' => begin
      %= input_tag 'title' => "$page->{title}", type => 'text', class => 'form-control', id => 'input_title',  placeholder => 'Page title'
  % end
% end

%= t div => class => 'form-group' => begin
    %= label_for 'input_content' => 'Content' => class => 'col-sm-2 control-label'
    %= t div => class => 'col-sm-10' => begin
      %= text_area 'content' => rows => 10 => class => 'col-sm-12' =>  begin
        %= $page->{content}
      % end
  % end
% end

%= t div => class => 'form-group' => begin
    %= label_for 'input_user_email' => 'Author' => class => 'col-sm-2 control-label'
    %= t div => class => 'col-sm-10' => begin
        %= input_tag 'user_email', type => 'text', class => 'form-control', id => 'input_user_email',  value =>  "$page->{user_email}"
    % end
% end

%= t div => class => 'form-group' => begin
    %= label_for 'input_created_at' => 'Create Date' => class => 'col-sm-2 control-label'
    %= t div => class => 'col-sm-10' => begin
        %= input_tag created_at => "$page->{created_at}", type => 'date', class => 'form-control', id => 'input_created_at'
  % end
% end


%= t div => class => 'form-group' => begin
    %= label_for 'input_can_show' => 'Show On Nav' => class => 'col-sm-2 control-label'
    %= t div => class => 'col-sm-10' => begin
      %= input_tag 'can_show', type => 'number', class => 'form-control', id => 'input_can_show', value => "$page->{can_show}"
  % end
% end


@@ page.html.ep
% layout 'default';

%= t h2 => $page->{title}
<hr>
%= t div => class => 'well' => begin
    %= $page->{content}
% end
<hr>
%= t p => begin
    %= t span => begin
        %= 'Author: ' .  $page->{user_email}
    % end

    %= t span => begin
        %= 'Date: ' . $page->{created_at }
    % end
% end
