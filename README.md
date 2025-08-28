# OpenCSF (imh-open-csf), v0.0.1

OpenCSF plugin for cPanel/WHM and CWP

- cPanel/WHM path: `/usr/local/cpanel/whostmgr/docroot/cgi/imh-open-csf/index.php`
- CWP path: `/usr/local/cwpsrv/htdocs/resources/admin/modules/imh-open-csf.php`

# Installation

- Run as the Root user: `curl -fsSL https://raw.githubusercontent.com/gemini2463/imh-open-csf/master/install.sh | sh`

# Files

## Shell installer

- install.sh

## Main script

- index.php - Identical to `imh-open-csf.php`.
- index.php.sha256 - `sha256sum index.php > index.php.sha256`
- imh-open-csf.php - Identical to `index.php`.
- imh-open-csf.php.sha256 - `sha256sum imh-open-csf.php > imh-open-csf.php.sha256`

## Icon

- imh-open-csf.png - [48x48 png image](https://api.docs.cpanel.net/guides/guide-to-whm-plugins/guide-to-whm-plugins-plugin-files/#icons)
- imh-open-csf.png.sha256 - `sha256sum imh-open-csf.png > imh-open-csf.png.sha256`

## cPanel conf

- imh-open-csf.conf - [AppConfig Configuration File](https://api.docs.cpanel.net/guides/guide-to-whm-plugins/guide-to-whm-plugins-appconfig-configuration-file)
- imh-open-csf.conf.sha256 - `sha256sum imh-open-csf.conf > imh-open-csf.conf.sha256`

## CWP include

- imh-plugins.php - [CWP include](https://wiki.centos-webpanel.com/how-to-build-a-cwp-module)
- imh-plugins.php.sha256 - `sha256sum imh-plugins.php > imh-plugins.php.sha256`

## sha256 one-liner

- `for file in index.php imh-plugins.php imh-open-csf.conf imh-open-csf.php imh-open-csf.png; do sha256sum "$file" > "$file.sha256"; done`
