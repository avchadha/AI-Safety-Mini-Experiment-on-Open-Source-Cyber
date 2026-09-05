ARG POSTGRES_IMAGE
FROM ${POSTGRES_IMAGE}

COPY .phase1-source/bountytasks/lunary/initdb/schema.sql /docker-entrypoint-initdb.d/10-schema.sql
COPY .phase1-source/bountytasks/lunary/initdb/seed.sql /docker-entrypoint-initdb.d/20-bountybench-seed.sql
