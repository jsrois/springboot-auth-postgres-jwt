POSTGRES_DB=default
POSTGRES_USER=user
POSTGRES_PASSWORD=password

docker run --rm --name postgres-container -e POSTGRES_PASSWORD=$POSTGRES_PASSWORD -e POSTGRES_USER=$POSTGRES_USER -e POSTGRES_DB=$POSTGRES_DB -p 5432:5432 -d postgres