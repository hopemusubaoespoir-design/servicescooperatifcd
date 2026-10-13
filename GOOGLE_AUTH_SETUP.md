# Configuration de la connexion Google

Cette version ajoute le bouton « Continuer avec Google » et une fonction Netlify qui réalise le flux OAuth côté serveur. La session est conservée pendant sept jours dans un cookie signé, HttpOnly, Secure et SameSite=Lax. Aucun jeton Google n'est enregistré et aucune table de comptes n'est créée ; les utilisateurs sont authentifiés, mais leurs comptes et rôles ne sont pas persistés dans une base de données.

## 1. Créer les identifiants OAuth Google

Dans Google Cloud Console, créez ou sélectionnez un projet, configurez l'écran de consentement OAuth, puis créez un identifiant client de type application Web.

- Origine JavaScript autorisée : la valeur stable de SITE_URL, par exemple https://votre-site.netlify.app.
- URI de redirection autorisée : la valeur de SITE_URL suivie de /.netlify/functions/google-auth?action=callback.

Utilisez l'URL principale et stable du site Netlify, pas une URL d'aperçu de déploiement avec un préfixe aléatoire.

## 2. Ajouter les variables dans Netlify

Dans le projet Netlify, ajoutez ces variables d'environnement et activez leur disponibilité pour les Functions :

GOOGLE_CLIENT_ID : l'identifiant client Web fourni par Google.
GOOGLE_CLIENT_SECRET : le secret client Google. Ne le mettez jamais dans GitHub ni dans le code navigateur.
SESSION_SECRET : une valeur aléatoire secrète d'au moins 32 caractères.
SITE_URL : l'URL HTTPS principale et stable du site, sans chemin supplémentaire.

Après avoir enregistré les variables, redéployez le site pour que la fonction les reçoive.

## 3. Vérifier

Ouvrez le site, cliquez sur « Continuer avec Google », choisissez un compte Google, puis vérifiez que l'adresse du compte apparaît à la place du bouton. Le bouton de déconnexion efface le cookie de session.

La fonction se trouve dans netlify/functions/google-auth.js, le dossier de fonctions par défaut de Netlify.
