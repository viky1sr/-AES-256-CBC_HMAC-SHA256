FROM php:8.4-cli

# System deps + pcntl (wajib untuk Workerman)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git unzip curl \
 && docker-php-ext-install pcntl \
 && rm -rf /var/lib/apt/lists/*

# Install Composer
RUN curl -sS https://getcomposer.org/installer | php -- \
    --install-dir=/usr/local/bin \
    --filename=composer

WORKDIR /app

# Install deps dulu biar layer cache bagus
COPY composer.json composer.lock ./
RUN composer install --no-interaction --prefer-dist --no-dev

# Copy project
COPY . .

# Start Workerman
CMD ["sh", "-lc", "php server.php start"]
