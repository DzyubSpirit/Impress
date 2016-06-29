cd ..
export IMPRESS_MODE=test
node --stack-trace-limit=1000 --allow-natives-syntax ./tests/integration.js
