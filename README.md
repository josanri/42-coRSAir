# Instalación
Para hacer uso del programa se requiere primero de la instalación de openssl o su compilación desde la carpeta de openssl. En ella ejecutaremos:
```
$ openssl-master> ./Configure
$ openssl-master> make
```
Tras un proceso algo largo, obtendremos libcrypto.a para nuestra máquina. Esta librería será la que usaremos a continuación para las operaciones con números grandes.
# Ejecutar
```
$ > make
$ > ./coRSAir -k clave_1 clave_2 -f archivo_cifrado1 archivo_cifrado2
```
# Elementos del cifrado en RSA
## Primos
```
p = Número primo 1

q = Número primo 2
```
## Módulo
```
n = p · q
```
## Theta
```
θ = (p - 1) · (q - 1)
```
## Exponente
### Exponente de cifrado
```
e = coprimo de θ, menor que θ, mayor que 1
```
### Exponente de descifrado
```
d = inv (e, θ)
```
, es el inverso multiplicativo del entero e, modulo θ. Intentaremos obtenerlo gracias a los primos comunes de distintos certificados de clave pública.
## Explicaciones matemáticas
### Coprimos
Un número coprimo con otro si su máximo común divisor (m.c.d) es 1.
### Inverso multiplicativo
El inverso multiplicativo de un número entero **n** módulo **p** es otro entero **m** (módulo p) tal que el producto m·n es congruente con 1;
El inverso multiplicativo de (y, z) es aquel número x tal que:
```
n · m = 1 (mod z)
```
El inverso multiplicativo de n módulo p existe si y solo si n y p son coprimos, algo que tenemos asegurado aquí entre e y θ.
Se puede obtener mediante el algoritmo de Euclides extendido.
# Claves
## Pública
La clave pública es (n, e), esto es, el módulo y el exponente de cifrado.
## Privada
La clave privada es (n , d), esto es, el módulo y el exponente de descifrado, que debe mantenerse en secreto.
# Algoritmo de cifrados vulnerables
Si leemos 100 certificados públicos de un sistema con baja entropía, es probable que en determinado momento se repita un primo en dos certificados, podemos comprobarlo con el algoritmo de Euclides (que el máximo común divisor no sea 1).

En un caso así, tenemos información suficiente para extraer n, la multiplicación de los dos primos y θ, la multiplicación de los dos (primos-1).

Puesto que el exponente e (cifrado) es público será sencillo obtener por Euclides extendido (de nuevo) el inverso y con ello, el exponente de descifrado, pudiendo a continuación descifrar el mensaje.
## Complejidad
Pasamos de tener ataques de fuerza bruta con una complejidad exponencial a tener que comprobar (n/2(n+1)) con una alta probabilidad de éxito si el sistema tiene baja entropía.
# Conclusiones
Un sistema con baja entropía es altamente vulnerable a ataques de certificados RSA. La elección de dos primos aleatorios puede no suponer un problema, pero no es trivial y ha de asegurar la distribución de primos que se generan.

Por otra parte, que un sistema coincida en primos parecería algo poco probable; sin embargo, en un sistema con baja entropía esto podría parecerse a la famosa paradoja del cumpleaños. Que coincidan dos primos podría no ser lo complicado, sino lo común, si la franja de primos se ve limitada.
# Comentarios
El algoritmo de RSA pasará a estar obsoleto según se consiga ejecutar el algoritmo de Shor con los qubits necesarios como para que la factorización de números se convierta en una tarea con complejidad logarítmica.

No obstante, hasta que esto pase, sigue siendo importante preservar la seguridad de los algoritmos de cifrado de legado a la vez que se migra a las nuevas soluciones de cifrados post-quántica.