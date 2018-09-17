# Catalog Project

## Project Overview
You will develop an application that provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.

## Why This Project?
Modern web applications perform a variety of functions and provide amazing features and utilities to their users; but deep down, it’s really all just creating, reading, updating and deleting data. In this project, you’ll combine your knowledge of building dynamic websites with persistent data storage to create a web application that provides a compelling service to your users.

## What Will I Learn?
You will learn how to develop a RESTful web application using the Python framework Flask along with implementing third-party OAuth authentication. You will then learn when to properly use the various HTTP methods available to you and how these methods relate to CRUD (create, read, update and delete) operations.

## How Does This Help My Career?
Efficiently interacting with data is the backbone upon which performant web applications are built
Properly implementing authentication mechanisms and appropriately mapping HTTP methods to CRUD operations are core features of a properly secured web application

## Setup

### Virtual Machine with Vagrant
***Requirements***

1. The VirtualBox VM environment
2. The Vagrant configuration program
3. Installing VirtualBox
4. Signup to Facebook Developer Console
5. Create an App on Facebook abd uodate the [fb_client_secrets.json](fb_client_secrets.json)
6. Sign up to Google Developer Console
7. Create an APP on Google and update the [client_secrets.json](client_secrets.json)
8. Update the [login.html](login.html) file with the app ids.

**VirtualBox** 
VirtualBox is the software that actually runs the virtual machine. You can download it from virtualbox.org, [here](https://www.virtualbox.org/wiki/Downloads). Install the platform package for your operating system. You do not need the extension pack or the SDK. You do not need to launch VirtualBox after installing it; Vagrant will do that.

**Installing Vagrant**
Vagrant is the program that will download a Linux operating system and run it inside the virtual machine. [Install it from this site](https://www.vagrantup.com/downloads.html).

Windows users: The Installer may ask you to grant network permissions to Vagrant or make a firewall exception. Be sure to allow this.

Bringing up the database server
Vagrant takes a configuration file called Vagrantfile that tells it how to start your Linux VM. All vagrant files for this project can be found in the vagrant folder of this repo [vagrant](vagrant). Once you have a copy of this in your machine go to that directory, and run the command ```$ vagrant up```. Once completed you should see something like this:

*Successful vagrant up results: "Done installing your virtual machine!"*

Now you have a PostgreSQL server running in a Linux virtual machine. This setup is independent of any other database or web services you might have running on your computer, for instance for other projects you might work on. The VM is linked to the directory where you ran vagrant up.

To log into the VM, use a terminal in that same directory and run the following command ```$ vagrant ssh```. You'll then see something like this:

*A shell prompt on the Vagrant-managed Linux VM.*

In this shell, if you change directory to /vagrant and run *ls* there, you will see the Vagrantfile you downloaded ... and any other files you put into that directory from your computer, that will be the shared folder between VM and your computer.

### Logged in!
If you are now looking at a shell prompt that starts with the word vagrant ex ```vagrant@vagrant:/vagrant$```, congratulations — you've gotten logged into your Linux VM.

## Environment
* Python  2.7.12
* Postgresql 9.5.13
* Bootstrap 3.3.7

