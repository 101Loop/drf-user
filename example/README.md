# About

---
This sample project demonstrates all the API endpoints of drf-user. It integrates with swagger so that all the API's can
be exported in openapi format.

# Running Example Project

---

1. Create and activate your virtual environment
2. Install requirements:
    ```shell
    (.venv) $ pip install -r requirements.txt
    ```
3. Run testing server:
    ```shell
    (.venv) $ python manage.py runserver
    ```
4. Take a look at `http://localhost:8000/swagger`. Swagger will list all the APIs of drf-user.
5. Go to `http://localhost:8000/swagger/?format=openapi`. From here you can export all the APIs in openapi format.
   Exported APIs can be easily imported into tools like [Postman](https://www.postman.com/).
