# Docker Stack Lamp:

The objective of this project is to show a clean and friendly terminal interface for the developer, in which the minimum parameters necessary for the execution of a LAMP stack based on docker can be established.

It does not require further knowledge in Docker, since the assembly of the parameter files is executed through scripting.

## READ all the Readme!!!

### Preparation for docker:

you need to have installed and Open docker/docker desktop and version WSL2.0 put off Ubuntu

### Installation of this setup:

1. Download or clone to where you want your project to be.
2. You should not put this in folders associated with Google Drive or One Drive this causes errors.
3. Open a Terminal (example: powershell) and locate in the cloned directory
4. Run this command

```PS
.\run.ps1
```

5. The executable will start the installation process requesting information on how you want to do the installation. Once you give it the information, it will install the containers in Docker for you and give you the access URLs.

### How do I access?

When you initialize the system, it will ask you for a series of data and then one of those data is the desired configuration of the urls. Once the configuration and installation of the entire environment in the terminal is complete, the system will tell you what the urls are, similar. in this view:

![finish installation view](https://i.imgur.com/EI6oVrD.png)


### Example videos:

Without SSL:

https://youtu.be/u9YtuHiZ4XI

With SSL:

https://youtu.be/j44xViK3Ass

### What does this stack lamp include?

- Self-signed SSL support and automatic generation.
- php 8.1 version
- custom entry point and project directory
- mysql 8 (latest)
- phpmyadmin (latest)
- cronjobs (via crontab-ui)

### Example Host File:

```
# Added by Docker Desktop
192.168.1.1 host.docker.internal
192.168.1.1 gateway.docker.internal
# To allow the same kube context to work on the host and the container:
127.0.0.1 kubernetes.docker.internal
# End of section

# Developer Area Docker
127.0.0.1 lh-stack.dock pma.lh-stack.dock cron.lh-stack.dock
# End of Area
```

Note: `Added by Docker Desktop` can be updated by `com.docker.service` and this refers to the DHCP or Static address that your device currently has as the Host Operating System.

### Some screenshots of the running environment:

Apache + Php 8.1 environment:

![apache php view](https://i.imgur.com/HpGyLdv.png)


phpMyAdmin environment:

![phpmyadmin view](https://i.imgur.com/U0AlW4p.png)

crontab-ui environment:

![crontab-ui view](https://i.imgur.com/7I40e1I.png)

### Contributing:

Thank you for considering contributing to the Docker Lamp Stack project!.

### Security Vulnerabilities
If you discover a security vulnerability within Docker Lamp Stack, please create issue and please contact the author and/or security team instead.

## License

The Docker Lamp Stack project is open-source software licensed under the GLP-3 license.


### Contributors
- (c) 2023 Walter Francisco Núñez Cruz icarosnet@gmail.com 

[![Donate](https://img.shields.io/static/v1?label=Donate&message=PayPal.me/wnunez86&color=brightgreen)](https://www.paypal.me/wnunez86/4.99USD)