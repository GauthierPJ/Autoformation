# CheatSheet pour Bash

## Quelques commandes à savoir 

* `cut -d [delimitateur] -f [colonne]` : affiche un fichier tq demandé (csv...)
* `tr -d [char]` : permet d'effacer un caractère
* `find | while read line ; do strings $line; done | grep -i "FLAG {"` : 
permet de chercher si "FLAG {" est contenu dans un fichier
* `hostname` : donne le nom du pc 
* Relancer la commande précédente avec sudo : `sudo !!`


## Variables

### Généralités

* Valeur d'une variable : `$x`
* Affectation : `x=a` (`x= a` ne fonctionne pas)
* Affectation par lecture : `read x`
Affichage d'une chaîne avant : `read -p "Entrez x : " x`
* Constante : `declare -r x=a`
* Suppression d'une variable : `unset x`

### Variable locale - globale

Les variables locales ont la portée de celle du **shell en cours**.

* Locale  : `x=a`
* Globale : `export x=a` 

### Paramètres de position

Commande `set` affecte une valeur de position commençant à 1.
* `set a b c` => `$1=a; $2=b; $3=c`
* `set --` => réinitialisation

### Paramètres spéciaux

* Nombre de paramètres : `$#`
* Tous les paramètres  : `$@`
* Nom du script        : `$0`
* Code d'erreur        : `$?` => 0 = aucune erreur

### Substitution de commandes

Syntaxe : `$(cmd)`

* Sauvegarde du pwd dans une variable : `x = $(pwd)`

## Instructions communes 

**WHILE**
```
while [cond] 
do
    [traitement]
done
```
L’originalité de cette structure de contrôle est que le test ne porte pas sur une condition booléenne (vraie ou fausse) mais sur le code de retour issu de l’exécution d’une suite de commandes.
`[cond]` n'est pas forcément une condtion : elle peut être une commande dont le code de retour est évalué.

**FOR**

Le pas n'est pas nécessaire
```
for i in {debut..fin..pas}
do 
    [traitement]
done
```

**SWITCH**

```
case [mot] in 
[ modèle [ | modèle ] ... ) suite_de_commandes ;; ]
*)                          commande_par_defaut
esac
```
# Chaînes de caractères

## Généralités
* Caractère d'échappement : `\`
* Longueur d'une chaine : `${#chaine}`

## Suppression de chaîne
* Suppression de la plus courte sous chaîne de gauche : `${param#modèle}`.
*Exemple :* `set "12344567" ; echo ${1#*4}` renvoie "4567".
* Suppression de la plus longue sous chaîne de gauche : `${param##modèle}`.
*Exemple :* `set "1234567890" ; echo ${1##*4}` renvoie "567".
* Suppression de la plus courte sous chaîne de droite : `${param%modèle}`.
*Exemple :* `set "12344567" ; echo ${1%4*}` renvoie "4567".
* Suppression de la plus longue sous chaîne de droite : `${param%%modèle}`.
*Exemple :* `set "1234567890" ; echo ${1%%4*}` renvoie "567".
**Conclusion suppression** : 
    1. `*4` => suppression la chaîne en partant de gauche jusqu'à la première (ou dernière, # ou ## resp) occurence de 4
    2. `4*` suppression de la chaîne en partant de droite jusqu'à la premire (ou dernière, % ou %% resp) occurence de 4

## Extraction de chaîne

* Syntaxe  `${paramètre:ind}` : extrait la sous chaîne débutant à "ind" (exclu).
*Exemple :* `x = "abcdefghijk" ; echo ${x:3}` renvoie `defghij`.
* Syntaxe `${paramètre:ind:nb}` : extrait nb caractères à partir de ind (exclu).
http://aral.iut-rodez.fr/fr/sanchis/enseignement/bash/ch09s05.html

# Flux entrée/sortie 

Il existe 3 flux en bash : STDIN (0), STDOUT(1), STDERR(2)

* `>`    : redirige STDOUT dans un fichier. 
* `2>`   : redirige les erreurs dans un fichier.
* `2>>`  : redirige les erreurs à la fin d'un fichier.
* `2>&1` : redirige les erreurs dans le même endroit et de la même façon que STDOUT.
* `[cmd] > log 2>&1` : redirige STDOUT et STDERR dans log.
* `[cmd] < [entrée]` : permet d'indiquer d'où vient l'entrée d'une commande.
Exemple : `cat < toto.txt` est équivalent à `cat toto.txt` 
* `[cmd] << EOF`: permet d'envoyer du contenu à la commande [cmd] jusqu'à ce qu'on tape EOF.
Exemple : `wc -m << EOF` puis `abcdef` puis `EOF` renvoie le nombre de caractère de abcdef.