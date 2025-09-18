# TC WebUI 👋

### Installation via Python pip 🐍

TC WebUI can be installed using pip, the Python package installer. Before proceeding, ensure you're using **Python 3.11** to avoid compatibility issues.

1. **Install TC WebUI**:
   Open your terminal and run the following command to install TC WebUI:

   ```bash
   pip install . --proxy http://127.0.0.1:7897 --trusted-host pypi.org --trusted-host files.pythonhosted.org
   ```

2. **Running TC WebUI**:
   After installation, you can start TC WebUI by executing:

   ```bash
   tc-webui serve
   ```

This will start the TC WebUI server, which you can access at [http://localhost:8080](http://localhost:8080)


### Installation with Default Configuration

- **If Ollama is on your computer**, use this command:

  ```bash
  docker run -d -p 3000:8080 --add-host=host.docker.internal:host-gateway -v tc-webui:/app/backend/data --name tc-webui --restart always ghcr.io/tc-webui/tc-webui:main
  ```

- **If Ollama is on a Different Server**, use this command:

  To connect to Ollama on another server, change the `OLLAMA_BASE_URL` to the server's URL:

  ```bash
  docker run -d -p 3000:8080 -e OLLAMA_BASE_URL=https://example.com -v tc-webui:/app/backend/data --name tc-webui --restart always ghcr.io/tc-webui/tc-webui:main
  ```

- **To run TC WebUI with Nvidia GPU support**, use this command:

  ```bash
  docker run -d -p 3000:8080 --gpus all --add-host=host.docker.internal:host-gateway -v tc-webui:/app/backend/data --name tc-webui --restart always ghcr.io/tc-webui/tc-webui:cuda
  ```

### Installation for OpenAI API Usage Only

- **If you're only using OpenAI API**, use this command:

  ```bash
  docker run -d -p 3000:8080 -e OPENAI_API_KEY=your_secret_key -v tc-webui:/app/backend/data --name tc-webui --restart always ghcr.io/tc-webui/tc-webui:main
  ```
