# Image that is going to be used
# Starts with a lightweight official Python image. 
# The slim tag avoids unnecessary OS packages, making your final image smaller.
FROM python:3.13-slim

# Label enables setting any metadata that is required that can be viewed easily
LABEL org.opencontainers.image.authors="alan.ramos@gmail.se"

# Sets the working directory inside the container to /app. All subsequent commands run from here.
WORKDIR /app

# Copies the dependencies file into the container's working directory.
COPY requirements.txt .

# Installs all dependencies. 
# The --no-cache-dir flag reduces the final image size.
RUN pip install --no-cache-dir -r requirements.txt

# Copies the entire Flask application code (including app.py, templates, etc.)
# into the /flaskr directory.
COPY . .

# Sets the environment variable telling Flask which file to run. 
ENV FLASK_APP=flaskr

# Informs Docker that the container listens on port 5000, 
# the default Flask port. Note: This doesn't publish the port; 
# Docker Compose or docker run -p does that.
EXPOSE 5001

# Running the process
# Defines the command to run the application. 
# Running on 0.0.0.0 is crucial for Docker, 
# as it makes the app accessible from outside the container's isolated network.
CMD ["flask", "run", "--host=0.0.0.0", "--port=5001"]