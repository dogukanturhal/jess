CREATE TABLE widgets (
    id    serial PRIMARY KEY,
    name  text NOT NULL,
    price numeric(8, 2) NOT NULL
);

INSERT INTO widgets (name, price) VALUES
    ('sprocket', 4.50),
    ('flange', 12.00),
    ('gasket', 0.75);
