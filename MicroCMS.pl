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
            'INSERT INTO user 
				(email, password, rule) 
				VALUES("admin@myproject.com","611020cac05ee652e41ffa30bba2cd1a", "3");'
        );
    },
};

sub get_users {
    return Model->selectall_arrayref( 'SELECT * from user', { Slice => {} }, );
}

sub get_rule {
    return Model->selectall_arrayref( 'SELECT rule from user where email = ?',
        { Slice => {} }, $_[0], );
}

sub get_messages {
    return Model->selectall_arrayref( 'SELECT * from entries', { Slice => {} },
    );
}

package main;

use Mojolicious::Lite;
use Mojo::ByteStream 'b';
use Mojo::Date;

# enable option if you using 4.90 or older version
#app->secret('MicroCMS791'); # Removed deprecated secret after version 4.91

helper auth => sub {
    my $self     = shift;
    my $email    = $self->param('email');
    my $password = b(app->secret . $self->param('password'))->md5_sum;

    if ( Model::User->count( 'WHERE email=? AND password=?', $email, $password )
        == 1 )
    {
        my $rule = Model::get_rule($email);
        $self->session( rule  => $rule->[0]->{rule} );
        $self->session( email => $email );
        return 1;
    }
    else {
        return;
    }
};

helper check_token => sub {
    my $self       = shift;
    my $validation = $self->validation;
    return $self->render( text => 'Bad CSRF token!', status => 403 )
      if $validation->csrf_protect->has_error('csrf_token');
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

under sub {
    my $self = shift;
    return 1 if $self->auth;
    return 1 if $self->session("email");
    $self->flash( failed_message => 'Access Denied!' );
    $self->redirect_to('/');
};

post '/login' => sub {
    my $self = shift;
    return if $self->check_token;
    $self->flash( sucess_message => 'Wellcome!' );
    $self->redirect_to('/');
};

get '/app/addmessage' => sub {
    my $self = shift;
    my $date = Mojo::Date->new(time);
    $self->stash( date => $date );
} => 'addmessage';

get '/app' => sub {
    my $self    = shift;
    my $mesages = Model::get_messages();
    $self->stash( mesages => $mesages );
} => 'app';

post '/app/addmessage' => sub {
    my $self = shift;
    return if $self->check_token;

    Model::Entries->create(
        email   => $self->param('email'),
        content => $self->param('message'),
        date    => $self->param('date'),
    );
    $self->flash( sucess_message => 'Create message sucessfull!' );
    $self->redirect_to('/app');
};

post '/app/delete/*id' => => sub {
    my $self = shift;
    return if $self->check_token;
    my $id = $self->stash('id');
    Model::Entries->delete_where( 'id=?', $id );
    my $mesages = Model::get_messages();
    $self->stash( mesages => $mesages );
    $self->flash( sucess_message => "Message sucessfull deleted!" );
    $self->redirect_to('/app');
};

under sub {
    my $self = shift;
    return 1 if $self->session("rule") == 3;
    $self->flash( failed_message => 'Permission denied!' );
    $self->render( 'index', status => '403' );
    return undef;
};

get '/admin/users' => sub {
    my $self  = shift;
    my $users = Model::get_users();
    $self->stash( users => $users );
};

get '/admin/adduser'        => 'adduser';
post '/admin/delete/*email' => => sub {
    my $self = shift;
    return if $self->check_token;
    my $email = $self->stash('email');
    Model::User->delete_where( 'email=?', $email );
    my $users = Model::get_users();
    $self->stash( users => $users );
    $self->flash(
        sucess_message => "User with the mail $email sucessfull deleted!" );
    $self->redirect_to('/admin/users');
};
post '/admin/adduser' => sub {
    my $self = shift;
    return if $self->check_token;

    if ( Model::User->count( 'WHERE email=?', $self->param('email') ) == 1 ) {
        $self->flash(
            failed_message => 'Duplicate email found! Can not create user!' );
        $self->redirect_to('/admin/users');
        return;
    }
    Model::User->create(
        email    => $self->param('email'),
        password => b(app->secret . $self->param('password'))->md5_sum,
        rule     => $self->param('rule'),
    );
    $self->flash( sucess_message => 'Create user sucessfull!' );
    $self->redirect_to('/admin/users');
};

app->start;

__DATA__
@@ default.html.ep

<!DOCTYPE html>
<html lang="en">
% content_for header => begin
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="">
  <meta name="author" content="">
%end
%= stylesheet '//netdna.bootstrapcdn.com/bootstrap/3.0.3/css/bootstrap.min.css'
%= stylesheet begin
body {
  padding-top: 50px;
  padding-bottom: 20px;
 }
%end
<body>
%= tag div => class => 'navbar navbar-inverse navbar-fixed-top' => role =>'navigation' => begin
 %= tag div => class => 'container' => begin
  %= tag div => class => 'navbar-header' => begin
	<button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-collapse">
	<span class="sr-only">Toggle navigation</span>
	<span class="icon-bar"></span>
	</button>
	<a class="navbar-brand" href="/">MicroCMS</a>
	<a class="navbar-brand" href="/help">Help</a>
  %end
  %= tag div => class => 'navbar-collapse collapse' => begin	  
	 % if (!session 'email') {
	 %= form_for '/login' => (method => 'post') => class =>'navbar-form navbar-right' => role => 'form'=> begin 
	  %= csrf_field
	  %= tag div => class => 'form-group' => begin
		%= text_field 'email', name => 'email', class => 'form-control', placeholder =>'email'
	  %end
	  %= tag div => class => 'form-group' => begin
		%= password_field 'password', name => 'password', class => 'form-control', placeholder =>'password'
	  %end 
		<button class="btn btn-success" type="submit">Login</button>
	 %end
	 % } else {
	  <ul class="nav navbar-nav">
	  % if (current_route 'index') { $self->stash( class => 'active') } else { $self->stash( class => '') }
		<li class="<%= stash 'class' %>" ><a href="/">Home</a></li>
	  % if ( (session 'rule') > 2 ) {
	  % if (current_route 'users') { $self->stash( class => 'active') } else { $self->stash( class => '') }
		<li class="<%= stash 'class' %>" ><a href="/admin/users">Admin</a></li>
	  %}
	  % if (current_route 'app') { $self->stash( class => 'active') } else { $self->stash( class => '') }
		<li class="<%= stash 'class' %>" ><a href="/app">App</a></li>
      </ul>
		%= form_for '/logout' => (method => 'get') => class =>'navbar-form navbar-right' => begin
		<button class="btn btn-success" type="submit">Logout <%= session 'email' %> </button>
		%end
	 %}
	 
  %end
%end
%end
%= tag div => class => 'container' => begin
  %= tag h1 => 'MicroCMS'
%end
<div class="container">

% if ( flash 'failed_message' || stash 'failed_message' ) {
<div class="alert alert-danger">
	%= flash 'failed_message'
	%= stash 'failed_message'
</div>
%}

% if ( flash 'sucess_message' || flash 'sucess_message' ) {
<div class="alert alert-success">
	%= flash 'sucess_message'
	%= stash 'sucess_message'
</div>
% }

%= content 

@@ footer.html.ep
<hr>
%= tag footer => begin
  %= tag p => "Powered by: MicroCMS" 
  %= link_to 'https://github.com/ovntatar/MicroCMS' => begin %>ovntatar<% end 
%end
</div>
%= javascript '//netdna.bootstrapcdn.com/bootstrap/3.0.3/js/bootstrap.min.js'
</body>
</html>

@@ index.html.ep
%= include 'default';

For demo please use the following details:<br>
Email <b>admin@myproject.com</b>, Password: <b>admin</b><br>
%= stash 'pw'
<hr>
<div class="panel panel-default">
  <div class="panel-heading">Message - title</div>
  <div class="panel-body">
  <ul>
    % for my $items (@$mesages) {
	  <li><%=$items->{content}%> - <%=$items->{email}%> </li>
	 %} 
  </ul>
  </div>
</div>
%= include 'footer';


@@ adminusers.html.ep
%= include 'default';

<a href="adduser"><button type="button" class="btn btn-primary btn-sm">Add new user</button></a>
<hr>
<table class="table table-striped">
  <thead>
	<tr>
	<th>email</th>
	<th>password</th>
	<th>rule</th>
	<th>Action</th>
	</tr>
  </thead>
  <tbody>
	% for my $items (@$users) {
	  <tr>
	  <td> <%=$items->{email}%> </td>
	  <td> <%=$items->{password}%></td>
	  <td> <%=$items->{rule}%></td>
	  <td>
	  %= form_for "delete/$items->{email}" => (method => 'post') => begin
	  %= csrf_field
	  <button type="submit" class="btn btn-primary btn-sm" >Delete</button>
	  %end 
	  </td>  
	  </tr>
	% }
  </tbody>
</table>

%= include 'footer';

@@ app.html.ep
%= include 'default';

<a href="app/addmessage"><button type="button" class="btn btn-primary btn-sm">Add new message</button></a>
<hr>
<table class="table table-striped">
  <thead>
	<tr>
	<th>email</th>
	<th>content</th>
	<th>date</th>
	<th>Action</th>
	</tr>
  </thead>
  <tbody>
	% for my $items (@$mesages) {
	  <tr>
	  <td> <%=$items->{email}%> </td>
	  <td> <%=$items->{content}%></td>
	  <td> <%=$items->{date}%></td>
	  <td>
	  %= form_for "app/delete/$items->{id}" => (method => 'post') => begin
	  %= csrf_field
	  <button type="submit" class="btn btn-primary btn-sm" 
	  % if ( (session 'rule') < 3 ) {
		disabled="disabled" 
      %}
      >Delete</button></td>
	  
	  %end 
	  </td>  
	  </tr>
	% }
  </tbody>
</table>

%= include 'footer';

@@ adduser.html.ep
%= include 'default';
%= t h3 => 'Add User'

%= form_for '/admin/adduser' => (method => 'post') => class =>'form-horizontal' => role => 'form'=> begin
%= csrf_field
  <div class="form-group">
	<label for="inputEmail3" class="col-sm-2 control-label">Email</label>
	<div class="col-sm-10">
	<input type="email" name="email" class="form-control" id="inputEmail3" placeholder="Email">
	</div>
  </div>
  <div class="form-group">
	<label for="inputPassword3" class="col-sm-2 control-label">Password</label>
	<div class="col-sm-10">
	<input type="password" name="password" class="form-control"  id="inputPassword3" placeholder="Password">
	</div>
  </div>
	
  <div class="form-group">
	<label for="inputNumber" class="col-sm-2 control-label">Rule</label>
	<div class="col-sm-10">
	<input type="number" name="rule" class="form-control"  id="inputNumber" placeholder="Rule">
	</div>
  </div>
  <div class="form-group">
	<div class="col-sm-offset-2 col-sm-10">
	<button type="submit" class="btn btn-default">Add User</button>
	</div>
  </div>
%end

%= include 'footer';



@@ addmessage.html.ep
%= include 'default';
%= t h3 => 'Add User'

%= form_for '/app/addmessage' => (method => 'post') => class =>'form-horizontal' => role => 'form'=> begin
%= csrf_field
  <div class="form-group">
	<label for="inputEmail3" class="col-sm-2 control-label">Email</label>
	<div class="col-sm-10">
	<input type="email" name="email" value="<%= session 'email' %>" class="form-control" id="inputEmail3" placeholder="Email">
	</div>
  </div>
  <div class="form-group">
	<label for="inputTxt" class="col-sm-2 control-label">Message</label>
	<div class="col-sm-10">
	<input type="txt" name="message" class="form-control"  id="inputTxt" placeholder="Message">
	</div>
  </div>
	
  <div class="form-group">
	<label for="inputDatetime" class="col-sm-2 control-label">Datetime</label>
	<div class="col-sm-10">
	<input type="txt" name="date" value="<%= stash 'date' %>" class="form-control"  id="inputDatetime" placeholder="Datetime">
	</div>
  </div>
  <div class="form-group">
	<div class="col-sm-offset-2 col-sm-10">
	<button type="submit" class="btn btn-default">Add Message</button>
	</div>
  </div>
%end

%= include 'footer';


@@ help.html.ep
%= include 'default';
%= t h3 => 'Help'

<p>Mojolicious lite and bootstrap based simple cms</p>

<b>requirements</b>

<ul>
<li>-	perl 5.10 to higher</li>
</ul>

<b>install</b>

<ul>
<li>-  $ curl get.mojolicio.us | sh</li>
start developer server
<li>-  $ morbo MicroCMS.pl</li>
or start production server
<li>-  $ hypnotoad MicroCMS.pl</li>

</ul>

%= include 'footer';


