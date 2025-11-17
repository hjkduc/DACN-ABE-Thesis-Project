# Sử dụng image Python chính thức
FROM python:3.9-slim-buster

# Thiết lập biến môi trường
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Thiết lập thư mục làm việc
WORKDIR /app

# Cài đặt các thư viện build
# Sửa lỗi kho lưu trữ (repository) EOL của Debian Buster
RUN sed -i 's/deb.debian.org/archive.debian.org/g' /etc/apt/sources.list \
    && sed -i '/buster-updates/d' /etc/apt/sources.list \
    && apt-get update && apt-get install -y \
    build-essential \
    libgmp-dev \
    libssl-dev \
    libffi-dev \
    python3-dev \
    git \
    wget \
    # autoconf (gói) là 2.69, chúng ta cần 2.71. Cài các gói build-deps cho nó.
    bison \
    flex \
    libtool \
    procps \
    m4 \
    && rm -rf /var/lib/apt/lists/*

# Cài đặt autoconf 2.71 từ mã nguồn (yêu cầu bởi pbc 1b5d226)
RUN wget https://ftp.gnu.org/gnu/autoconf/autoconf-2.71.tar.gz && \
    tar -xvzf autoconf-2.71.tar.gz && \
    cd autoconf-2.71 && \
    ./configure && \
    make && \
    make install && \
    cd .. && \
    rm -rf autoconf-2.71 autoconf-2.71.tar.gz

# Cài đặt PBC từ mã nguồn
RUN git clone --depth 1 https://github.com/blynn/pbc.git /pbc && \
    cd /pbc && \
    git fetch --unshallow && \
    git reset --hard 1b5d226de4788bdcd1d47781c746c4192de5b69c -- && \
    mkdir m4 && \
    wget "https://git.savannah.gnu.org/gitweb/?p=autoconf-archive.git;a=blob_plain;f=m4/ax_cxx_compile_stdcxx.m4" -O m4/ax_cxx_compile_stdcxx.m4 && \
    wget "https://git.savannah.gnu.org/gitweb/?p=autoconf-archive.git;a=blob_plain;f=m4/ax_cxx_compile_stdcxx_14.m4" -O m4/ax_cxx_compile_stdcxx_14.m4 && \
    export ACLOCAL_PATH=/usr/share/aclocal && \
    autoreconf -i && \
    ./configure && \
    make && \
    make install && \
    ldconfig && \
    cd /app

# Clone và cài đặt Charm-Crypto từ mã nguồn
RUN git clone --depth 1 https://github.com/JHUISI/charm.git /charm && \
    cd /charm && \
    git fetch --unshallow && \
    git reset --hard bf9933fe843a0b78c07991452114fc4e4be2e71a -- && \
    ./configure.sh && \
    make && \
    make install && \
    pip install -e /charm && \
    cd /app

# Copy tệp requirements
COPY requirements.txt /app/

# Cài đặt các thư viện Python
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install gunicorn

# Copy phần code còn lại của ứng dụng
COPY . /app/

# Cấp quyền thực thi (execute) cho tệp entrypoint
RUN chmod +x /app/entrypoint.sh

# Mở cổng mà ứng dụng chạy
EXPOSE 8080
# Cổng debug
EXPOSE 5678

ENTRYPOINT ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "4", "--threads", "10", "--preload", "run:app"]

# ENTRYPOINT ["python", "-m", "watchmedo", "auto-restart", "--directory=.", "--pattern=*", "--recursive", "--", "python", "-m", "debugpy", "--listen", "0.0.0.0:5679", "run.py"]

# Debugging
# CMD ["python", "-m", "debugpy", "--listen", "0.0.0.0:5679", "run.py"]

# Development
# CMD ["watchmedo", "auto-restart", "--directory=.", "--pattern=*.py", "--recursive", "--", "python", "-m", "debugpy", "--listen", "0.0.0.0:5678", "--wait-for-client", "run.py"]