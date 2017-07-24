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
				VALUES("admin@myproject.com","21232f297a57a5a743894a0e4a801fc3", "3");'
        );
    },
};

sub get_users {
    return Model->selectall_arrayref('SELECT * from user', { Slice => {} },);
}

sub get_rule {
    return Model->selectall_arrayref('SELECT rule from user where email = ?', { Slice => {} }, $_[0],);
}

sub get_messages {
    return Model->selectall_arrayref('SELECT * from entries', { Slice => {} },);
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
    my $password = b($self->param('password'))->md5_sum;

    if (Model::User->count('WHERE email=? AND password=?', $email, $password) == 1) {
        my $rule = Model::get_rule($email);
        $self->session(rule  => $rule->[0]->{rule});
        $self->session(email => $email);
        return 1;
    }
    else {
        return;
    }
};

helper check_token => sub {
    my $self       = shift;
    my $validation = $self->validation;
    return $self->render(text => 'Bad CSRF token!', status => 403)
        if $validation->csrf_protect->has_error('csrf_token');
};

get '/' => sub {
    my $self    = shift;
    my $mesages = Model::get_messages();
    $self->stash(mesages => $mesages);
} => 'index';

get '/help' => 'help';

get '/logout' => sub {
    my $self = shift;
    $self->session(expires => 1);
    $self->redirect_to('/');
};

under sub {
    my $self = shift;
    return 1 if $self->auth;
    return 1 if $self->session("email");
    $self->flash(failed_message => 'Access Denied!');
    $self->redirect_to('/');
};

post '/login' => sub {
    my $self = shift;
    return if $self->check_token;
    $self->flash(sucess_message => 'Wellcome!');
    $self->redirect_to('/');
};

get '/app/addmessage' => sub {
    my $self = shift;
    my $date = Mojo::Date->new(time);
    $self->stash(date => $date);
} => 'addmessage';

get '/app' => sub {
    my $self    = shift;
    my $mesages = Model::get_messages();
    $self->stash(mesages => $mesages);
} => 'app';

post '/app/addmessage' => sub {
    my $self = shift;
    return if $self->check_token;

    Model::Entries->create(
        email   => $self->param('email'),
        content => $self->param('message'),
        date    => $self->param('date'),
    );
    $self->flash(sucess_message => 'Create message sucessfull!');
    $self->redirect_to('/app');
};

post '/app/delete/*id' => => sub {
    my $self = shift;
    return if $self->check_token;
    my $id = $self->stash('id');
    Model::Entries->delete_where('id=?', $id);
    my $mesages = Model::get_messages();
    $self->stash(mesages => $mesages);
    $self->flash(sucess_message => "Message sucessfull deleted!");
    $self->redirect_to('/app');
};

under sub {
    my $self = shift;
    return 1 if $self->session("rule") == 3;
    $self->flash(failed_message => 'Permission denied!');
    $self->render('index', status => '403');
    return undef;
};

get '/admin/users' => sub {
    my $self  = shift;
    my $users = Model::get_users();
    $self->stash(users => $users);
};

get '/admin/adduser'        => 'adduser';
post '/admin/delete/*email' => => sub {
    my $self = shift;
    return if $self->check_token;
    my $email = $self->stash('email');
    Model::User->delete_where('email=?', $email);
    my $users = Model::get_users();
    $self->stash(users => $users);
    $self->flash(sucess_message => "User with the mail $email sucessfull deleted!");
    $self->redirect_to('/admin/users');
};
post '/admin/adduser' => sub {
    my $self = shift;
    return if $self->check_token;

    if (Model::User->count('WHERE email=?', $self->param('email')) == 1) {
        $self->flash(failed_message => 'Duplicate email found! Can not create user!');
        $self->redirect_to('/admin/users');
        return;
    }
    Model::User->create(
        email    => $self->param('email'),
        password => b($self->param('password'))->md5_sum,
        rule     => $self->param('rule'),
    );
    $self->flash(sucess_message => 'Create user sucessfull!');
    $self->redirect_to('/admin/users');
};

app->start;

__DATA__
@@ layouts/default.html.ep

<!DOCTYPE html>
<html lang="en">
%= tag header => begin
  %= tag meta => charset => 'utf-8'
  %= tag meta => name => 'viewport'  => content=>'width=device-width, initial-scale=1.0'
  %= tag meta => name => 'description' => content=>''
  %= tag meta => name=> 'author' => content=>''
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
    %= tag div => class => 'navbar-header test111' => begin
	    %= tag button => type=>'button' => class=> 'navbar-toggle' => 'data-toggle' => 'collapse' => 'data-target' => '.navbar-collapse' => begin
	      %= tag span => class => 'sr-only' => 'Toggle navigation'
	      %= tag span => class => 'icon-bar'
      %end

      %= link_to 'MicroCMS' => '/' => class => 'navbar-brand'
	    %= link_to 'Help' => '/help' => class => 'navbar-brand'
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
          %= submit_button 'Login', class => 'btn btn-success'
        %end
  	 % } else {
        %= tag ul => class => 'nav navbar-nav' => begin
  	      % current_route eq 'index' ?  $self->stash( class => 'active') :  $self->stash( class => '');
  		    <li class="<%= stash 'class' %>" ><a href="/">Home</a></li>
  
          % if ( (session 'rule') > 2 ) {
  	        % current_route eq 'adminusers' ? $self->stash( class => 'active') : $self->stash( class => '');
  		      <li class="<%= stash 'class' %>" ><a href="/admin/users">Admin</a></li>
  	      %}
  	  
          % current_route eq 'app' ? $self->stash( class => 'active') : $self->stash( class => '');
  		    <li class="<%= stash 'class' %>" ><a href="/app">App</a></li>
        %end
  		
        %= form_for '/logout' => method => 'get' => class =>'navbar-form navbar-right' => begin
          % my $text = 'Logout ' . session 'email'; 
          %= submit_button $text => class => 'btn btn-success'
  		  %end
  	 %}
    %end
  %end
%end


%= tag div => class => 'container' => begin
  % if ( flash 'failed_message' || stash 'failed_message' ) {
  %= t div => class=> 'alert alert-danger' => begin
	  %= flash 'failed_message'
	  %= stash 'failed_message'
  %end
  %}

  % if ( flash 'sucess_message' || flash 'sucess_message' ) {
  %= tag div => class=>'alert alert-success' => begin
	  %= flash 'sucess_message'
	  %= stash 'sucess_message'
  %end
  %}
  
  %= tag div => class => '' => style => 'margin-top: 20px' => content 
%end

%= stylesheet begin
.footer {
  bottom: 0;
  width: 100%;
  background-color: #000000;
  height: 50px;
% end

%= tag footer => id => 'footer' => class => 'footer navbar-fixed-bottom' => begin
  %= tag div => class => 'container' => begin
    <br>
    %= tag p => class => 'text-muted' => begin
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

%= tag h1 => 'MicroCMS'

For demo please use the following details:<br>
Email <b>admin@myproject.com</b>, Password: <b>admin</b><br>
%= stash 'pw'
<hr>

%= tag div => class => 'panel panel-default' => begin
  %= tag div => class => 'panel-heading' => 'Message - title'
  %= tag div => class => 'panel-body' => begin
    %= tag ul => begin
      % for my $item (@$mesages) {
        % my $item_str = sprintf( '%s - %s', $item->{content}, $item->{email} );
	      %= tag li => begin
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

%= tag table => class => 'table table-striped' => begin
  %= tag thead => begin
	  %= tag tr => begin
	    %= tag th => 'email'
      %= tag th => 'password'
	    %= tag th => 'rule'
	    %= tag th => 'Action'
    % end
  % end

  %= tag tbody => begin
  	% for my $items (@$users) {
  	  %= tag tr => begin
  	    %= tag td => $items->{email}
  	    %= tag td => $items->{password}
  	    %= tag td => $items->{rule}
        %= tag td => begin
          %= form_for "delete/$items->{email}" => (method => 'post') => begin
  	        %= csrf_field
  	        %= submit_button 'Delete' => class => 'btn btn-primary btn-sm'
  	      %end 
        % end
      % end
  	%}
  % end
% end


@@ app.html.ep
% layout 'default';

%= link_to 'Add new message' => 'app/addmessage' => class => 'btn btn-primary btn-sm'
<hr>

%= tag table => class => 'table table-striped' => begin
  %= tag thead => begin
	  %= tag tr => begin
	    %= tag th => 'email'
	    %= tag th => 'content'
	    %= tag th => 'date'
	    %= tag th => 'Action'
    % end
  % end
  
  %= tag tbody => begin
	  % for my $item (@$mesages) {
	    %= tag tr => begin
	      %= tag td => $item->{email}
	      %= tag td => $item->{content}
	      %= tag td => $item->{date}
	      %= tag td => begin
	        %= form_for "app/delete/$item->{id}" => method => 'post' => begin
	          %= csrf_field
            %= submit_button 'Delete' => class => 'btn btn-primary btn-sm' => disabled => session->{rule} < 3 ? 'disabled' : ''
          % end
	      % end 
	    % end 
	  %}
	% end 
% end

@@ adduser.html.ep
% layout 'default';

%= t h3 => 'Add User'
<hr>
%= form_for '/admin/adduser' => method => 'post' => class =>'form-horizontal' => role => 'form'=> begin
  %= csrf_field
  %= tag div => class => 'form-group' => begin
	  %= label_for 'inputEmail3' => 'Email' => class => 'col-sm-2 control-label'
	  %= tag div => class => 'col-sm-10' => begin
	    %= input_tag 'email', type => 'email', class => 'form-control', id => 'inputEmail3',  placeholder => 'Email'
    % end
  % end

  %= tag div => class => 'form-group' => begin
	  %= label_for 'inputPassword3' => 'Password' => class => 'col-sm-2 control-label'
	  %= tag div => class => 'col-sm-10' => begin
	    %= input_tag 'password', type => 'password', class => 'form-control', id => 'inputPassword3', placeholder => 'Password'
    % end
  % end

  %= tag div => class => 'form-group' => begin
	  %= label_for 'inputNumber' => 'Rule' => class => 'col-sm-2 control-label'
	  %= tag div => class => 'col-sm-10' => begin
	    %= input_tag 'rule', type => 'number', class => 'form-control', id => 'inputNumber', placeholder => 'Rule'
    % end
  % end

  %= tag div => class => 'form-group' => begin 
	  %= tag div => class => 'col-sm-offset-2 col-sm-10' => begin
	    %= submit_button 'Add User' => class => 'btn btn-default'
    % end
  % end
%end

@@ addmessage.html.ep
% layout 'default';

%= t h3 => 'Add Message'

%= form_for '/app/addmessage' => method => 'post' => class =>'form-horizontal' => role => 'form'=> begin
  %= csrf_field
  %= tag div => class => "form-group" => begin
	  %= label_for 'inputEmail3' => 'Email' => class => 'col-sm-2 control-label'
	  %= tag div => class => 'col-sm-10' => begin
      %= input_tag 'email' => session->{email}, type => 'email', class => 'form-control', id => 'inputEmail3', placeholder => 'Email'
    % end
  % end

  %= tag div => class => 'form-group' => begin
	  %= label_for 'inputTxt' => 'Message' => class => 'col-sm-2 control-label'
	  %= tag div => class => 'col-sm-10' => begin
	    %= input_tag 'message', type => 'text', class => 'form-control', id => 'inputTxt', placeholder => 'Message'
    % end
  % end
	
  %= tag div => class=> 'form-group' => begin
	  %= label_for 'inputDatetime' => 'Datetime' => class => 'col-sm-2 control-label'
	  %= tag div => class => 'col-sm-10' => begin
	    %= input_tag 'date' => stash->{date}, type => "text",  class => 'form-control', id => 'inputDatetime', placeholder => 'Datetime'
    % end
  % end

  %= tag div => class => 'form-group' => begin
	  %= tag div => class => 'col-sm-offset-2 col-sm-10' => begin
      %= submit_button 'Add Message' => class => 'btn btn-default'
    % end
  % end 
%end

@@ help.html.ep
% layout 'default';

%= t h3 => 'Help'

%= tag p => 'Mojolicious lite and bootstrap based simple cms'
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

