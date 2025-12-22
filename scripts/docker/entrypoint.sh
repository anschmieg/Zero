#!/bin/sh
set -x

# Replacing placeholder urls to runtime variables, since we're using rewrites in nextjs, this is required.
# Everything else which doesn't compile URLs at build should already be able to use runtime variables.

/app/scripts/replace-placeholder.sh "http://REPLACE-BACKEND-URL.com" "$NEXT_PUBLIC_BACKEND_URL"
/app/scripts/replace-placeholder.sh "http://REPLACE-APP-URL.com" "$NEXT_PUBLIC_APP_URL"

# Run database migrations with error handling (safe fallback)
echo "Running database migrations..."
if cd /app/apps/server && pnpm run db:migrate; then
    echo "Migrations completed successfully"
else
    echo "WARNING: Migrations failed, but continuing to start server..."
fi
cd /app


ls -la /app/apps/mail/build && exec npx serve@latest /app/apps/mail/build -l 3000
