#Multi User Blog

## Set-Up Instructions:
1. Log in to http://console.cloud.google.com
1. Click Create a project...
1. Name the project and create it. Note the project ID.
1. Open app.yaml and replace PROJECT_ID_HERE with your project id.
1. Open blog.py and replace SECRET = 'secretkeyhere' with a secret key.
1. In Google App Engine Launcher, click File - Add existing application. Browse to your project and add it.
1. Click Run to run locally. GAE will show you the admin and app ports, usually 8000 and 8080. You can access the project in your browser at localhost:app-port.
1. Click Deploy to send your project to the Google Cloud Platform. It will be available at YOUR_PROJECT_ID.appspot.com.