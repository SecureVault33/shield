# Générer l'installeur SecureVault

## Prérequis

1. Compiler le binaire release d'abord (depuis la racine du projet) :

   ```
   cargo build --release
   ```

   Ceci doit produire `target\release\securevault.exe`. L'installeur copie ce
   fichier tel quel — le recompiler après toute modification du code source.

2. Installer Inno Setup (gratuit) depuis <https://jrsoftware.org/isdl.php>.
   Prendre la dernière version stable d'Inno Setup 6. Les composants par
   défaut suffisent (pas besoin de cocher de langue additionnelle).

## Compiler l'installeur

### Via l'interface graphique

1. Ouvrir `installer/setup.iss` dans Inno Setup (double-clic, ou
   Fichier → Ouvrir depuis Inno Setup).
2. Compiler avec **Ctrl+F9** (ou menu Compilation → Compiler).
3. L'installeur `SecureVault_Setup.exe` est généré dans `installer/Output/`.

### Via la ligne de commande

Depuis une invite où `ISCC.exe` est accessible (ajouté au PATH par
l'installeur d'Inno Setup, ou chemin complet vers
`C:\Program Files (x86)\Inno Setup 6\ISCC.exe`) :

```
ISCC.exe installer\setup.iss
```

## Ce que fait l'installeur

- Copie `securevault.exe` dans `{Program Files}\SecureVault\`.
- Lance `securevault.exe install` juste après la copie des fichiers, pour
  enregistrer le menu contextuel de l'Explorateur et l'association du
  fichier compagnon `.securevault`. Ces entrées sont écrites dans le registre
  de l'utilisateur courant (`HKCU`) — c'est pourquoi cette étape utilise
  l'indicateur `runascurrentuser`, même si l'installeur lui-même tourne en
  administrateur (nécessaire pour écrire dans `Program Files`).
- Ajoute une entrée dans *Programmes et fonctionnalités* (comportement par
  défaut d'Inno Setup, aucune configuration supplémentaire requise).
- À la désinstallation, lance `securevault.exe uninstall` (nettoie le
  registre) **avant** de supprimer les fichiers, puis supprime entièrement le
  dossier d'installation.

## Note

`securevault.exe install`/`uninstall` affichent chacun une popup de
confirmation (voir `ui::show_info`) à la fin de l'opération. Comme
l'installeur attend la fin du process avant de continuer (comportement par
défaut d'Inno Setup), il faudra fermer cette popup manuellement pour que
l'assistant d'installation/désinstallation poursuive. C'est normal, pas un
bug du script.
