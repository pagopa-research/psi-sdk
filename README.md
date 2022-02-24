# PSI-SDK

This Java library offers the core functionalities needed to implement an end-to-end Private Set Intersection protocol (PSI). Private Set Intersection is a secure multiparty computation that allows two parties to compute the intersection of
their encrypted datasets without revealing anything outside the intersection (or as close as possible to anything).

In the literature, we can find multiple alternative PSI algorithms based on different cryptographic primitives. This
library provides an implementation of the following algorithms:

- Blind Signature PSI (BS).
- Diffie-Hellman PSI (DH).
- Blind Signature PSI based on Elliptic Curves (ECBS).
- Diffie-Hellman PSI based on Elliptic Curves (ECDH).

The description of these algorithms, as well as their detailed comparison, can be found
in [this file](documentation/PSI-report-v1.1.pdf) (currently only available in italian).

An example showing a client-server PSI implementation based on this library can be found on the following
repositories: [server](https://github.com/alessandropellegrini/psi-demo-server)
, [client](https://github.com/alessandropellegrini/psi-demo-client).

The elliptic curve implementation is partially based on the [Bouncy Castle library](https://www.bouncycastle.org/java.html).

## Building

The build process is based on Maven. To generate the jar file (which will be located in the target folder) run the
following command:

    mvn clean install

The generated jar is automatically installed on the local maven repository.

## JavaDoc

A detailed description of all the classes and methods contained in this repository can be obtained by generating the
JavaDoc of this library with the following command:

    mvn javadoc:javadoc

By default, the JavaDoc generated through this command will be located in the folder
<code>target/site/apidocs</code>.

## General approach

Based on the specific PSI algorithm, the cryptographic operations performed by the parties might differ. To cope with
this distinction, this library is based on a client-server abstraction that considers as client the party that starts
new PSI calculations (also referred as sessions) and that is interested in getting the result of the intersection, while
the server is a passive party that answers the requests made by the client and has no interest in acquiring the result
of the PSI. As a consequence of this approach, we note that the problem of computing the result of the PSI in a single
session for both parties is outside the scope of this library and that it might not be feasible for all the supported
PSI algorithms.

Following the client-server paradigm, the core PSI functionalities are provided by two distinct classes: 
<code>PsiServer</code> and <code>PsiClient</code>. Remarkably, the interface of these classes is independent of the specific
PSI algorithm, and can be generated from the respective factory classes: <code>PsiServerFactory</code> and 
<code>PsiClientFactory</code>. The configuration of the PSI calculation
(such as the selection of the algorithm, the keys used for encryption, the cache configuration or the number of threads
used by the computation) is defined at the moment of the creation of the <code>PsiServer</code> and 
<code>PsiClient</code> objects by calling the proper factory methods. After the creation of these objects, the subsequent
steps of the PSI computation are the same for all the algorithms or configurations.

The <code>PsiServer</code> class is designed to operate on portions of the datasets, and does not require loading the
entire datasets in-memory. Conversely, the <code>PsiClient</code> requires loading different representations of the
datasets in-memory. There are two main reasons that motivate this alternative approach. First, in traditional
client-server scenarios, we can expect that the server might run multiple PSI sessions in parallel with different
clients, each with their peculiar datasets, which makes loading all of them in-memory unfeasible. Second, by not being
interested in acquiring the result of the PSI, the server does not need to store any representation of the client
dataset (either in-memory or on disk). An alternative approach where the <code>PsiClient</code> relies on secondary
storage to load different representations of the datasets is feasible but would result in a more complex interface and
degraded performance. The implementation of this approach is not provided by this repository.

In its external interface, either in input or output, this library considers the items of the datasets as sets of type
String. Internally, the String objects are converted to BigInteger objects after being read to speed up the execution of
encryption operations, and are converted back to String before being returned to the user. This approach simplifies the
interface of the library as strings can be easily serialized and deserialized (either for network communications or
database interactions).

The package structure of this repository is mostly motivated by visibility concerns. A notable exception is the
<code>model</code> package which contains the objects that define the data-layer of the PSI protocol, which, based on
the specific implementations, could either be used in communications or stored in stable storage.

## PSI calculation steps

This library provides an abstraction of the steps that constitute a PSI calculation. This allows its users to compute
the PSI, for any of the supported algorithm or configuration, by calling the same sequence of methods on the
<code>PsiServer</code> and <code>PsiClient</code> objects.

From a high-level abstraction, the client computes the PSI by comparing the following representations of the two
datasets:

- a server-side encryption of the client-side encryption of the client dataset;
- a client-side encryption of the server-side encryption of the server dataset.

To reach this state, the client dataset should undergo the following transformations:

1. Load the client dataset on the <code>PsiClient</code> object by calling the <code>loadAndEncryptClientDataset</code>
   method which converts the dataset to a map by assigning to each item an identifier. If required by the algorithm, it
   also applies a hash function to the dataset.
2. Encrypt the resulting dataset map by calling the <code>encryptClientDataset</code> method of the
   <code>PsiClient</code> object. The actual encryption operations performed by this method depend on the specific PSI
   algorithm.
3. The result of the client-side encryption is passed to the <code>encryptDatasetMap</code> method of the
   <code>PsiServer</code> object, which applies algorithm-specific encryption operations.
4. The result is loaded by the <code>PsiClient</code> object by calling the
   <code>loadDoubleEncryptedClientDataset</code> method.

Conversely, the transformations that should be applied to the server dataset are the following:

1. The server dataset is encrypted by the <code>PsiServer</code> object by calling the <code>encryptDataset</code>
   method. The encryption operations applied by this method depend on the specific PSI algorithm.
2. The resulting set is processed and loaded by the <code>PsiClient</code> object by calling the
   <code>loadAndProcessServerDataset</code> method. Based on the PSI algorithm, the processing portion of this method
   might apply algorithm-specific encryption operations.

Once these representations of the datasets are loaded on the <code>PsiClient</code> object, the result of the PSI can be
computed by calling the <code>computePsi</code> method.

## Example of use

In this section we provide a basic example showing how the library could be used to run a PSI calculation in a
simplified scenario where a single system acts both as the client and the server. In actual client-server environments,
any data transfer between the <code>PsiServer</code> and the <code>PsiClient</code> objects should be implemented
through proper communication primitives, such as REST APIs.

```
// Could be any supported pair of PsiAlgorithm and key size
PsiAlgorithmParameter psiAlgorithmParameter = new PsiAlgorithmParameter(PsiAlgorithm.BS, 2048)

// PsiServerSession objects containing the session metadata required to init PsiServer objects
PsiServerSession psiServerSession = PsiServerFactory.initSession(psiAlgorithmParameter);
PsiServer psiServer = PsiServerFactory.loadSession(psiServerSession);

// PsiClientSession objects are generated from PsiServerSession objects by 
// removing any references to private key fields.
PsiClientSession psiClientSession = PsiClientSession.getFromServerSession(psiServerSession);
PsiClient psiClient = PsiClientFactory.loadSession(psiClientSession);

// Client loads the double encrypted client dataset map
Map<Long, String> clientEncryptedDatasetMap = psiClient.loadAndEncryptClientDataset(clientDataset);
Map<Long, String> doubleEncryptedClientDatasetMap = psiServer.encryptDatasetMap(clientEncryptedDatasetMap);
psiClient.loadDoubleEncryptedClientDataset(doubleEncryptedClientDatasetMap);

// Client loads and processes the encrypted server dataset
Set<String> serverEncryptedDataset = psiServer.encryptDataset(serverDataset);
psiClient.loadAndProcessServerDataset(serverEncryptedDataset);

// Compute PSI
Set<String> psiResult = psiClient.computePsi();
```

We note that in this example, the entire datasets are always passed as inputs of the methods. However, the
methods <code>loadAndEncryptClientDataset</code>,
<code>loadDoubleEncryptedClientDataset</code> and <code>loadAndProcessServerDataset</code>
of the <code>PsiClient</code> class, as well as the methods <code>encryptDataset</code>
and <code>encryptDatasetMap</code> of the <code>PsiServer</code> class, which in this example are called once each,
could be called multiple times (even concurrently) to encrypt or load different portions of the datasets. Moreover, the
operations on the client dataset and the server datasets could be performed in different order or even concurrently. The
only requirement for computing a correct result of the PSI is that the final representations of the two datasets should
be completely loaded by the <code>PsiClient</code> object before calling the <code>computePsi</code> method.

## Key management

In this repository, we refer to keys as the instances of the <code>PsiKeyDescription</code>
interface which contain the security parameters used to set up the encryption functions of the <code>PsiServer</code>
and <code>PsiClient</code> objects. The <code>PsiKeyDescription</code> interface is implemented by the
<code>PsiServerKeyDescription</code> and <code>PsiClientKeyDescription</code> classes, which contain the all the
security parameters used by the supported PSI algorithms. Independently of their source type, all the fields of the keys
are converted to the String type to simplify their serialization and deserialization.

In the previous example, the keys are generated automatically by the library when creating the PSI objects. In
particular, the <code>PsiServer</code> keys are generated based on the input <code>PsiAlgorithmParameter</code>
object passed as parameter to the <code>initSession</code> method of the <code>PsiServerFactory</code> class.
Conversely, based on the specific PSI algorithm, the <code>PsiClient</code> might generate its own private key (DH or
ECDH) matching the parameters set by the <code>PsiServer</code>, or directly use the public key of the <code>
PsiServer</code> (BS or ECBS).

In addition to generating the keys automatically, the methods of the <code>PsiServerFactory</code> and the
<code>PsiClientFactory</code> classes also allow to provide an external <code>PsiKeyDescription</code> when generating
the <code>PsiServer</code> and <code>PsiClient</code> objects. This allows the users of the library to generate its keys
externally, or save previously used keys for subsequent executions, which, as discussed in the following section, is
essential to achieve performance speed-up through caching.

Users of this library can create instances of <code>PsiServerKeyDescription</code> and
<code>PsiClientKeyDescription</code> objects through their respective factory classes
(<code>PsiServerKeyDescriptionFactory</code> and <code>PsiClientKeyDescriptionFactory</code>). These classes offer
specific methods for each PSI algorithm, allowing the users to only provide the parameters that are relevant for the
selected algorithm. Moreover, the users can either pass the input parameters as String objects (which is the format
exported directly by the library) or as standard key specifications objects. In particular, the keys associated to the
BS algorithm can be generated from <code>RSAPrivateKeySpec</code> and <code>RSAPublicKeySpec</code> objects (Java
Security), DH keys can be generated from <code>DHPrivateKeySpec</code> objects (Java Security), and keys associated to
the ECBS and ECDH algorithms can be generated from
<code>ECPrivateKey</code> and <code>ECPublicKey</code> objects (Bouncy Castle).

## Caching

The computational cost of encryption operations, in particular when using relatively large keys, can be significant. For
PSI calculations that use the same keys, saving the result of encryption operations, and then reading these values in
subsequent executions (instead than performing once again the encryption operations) can result in significant
performance improvements. However, the actual implementation of the caching layer, which could be based on external
systems, in-memory data structures or databases, is highly dependent on the specific implementation, and thus, is not
provided directly by this library.

To support caching while also offering flexibility and ease-of-use, this library exposes a
<code>PsiCacheProvider</code> interface, which requires its users to implement a simple key-store interface constituted
by a <code>put</code> and a <code>get</code> method. Internally, the library relies on BASE64 and JSON conversions to
convert complex objects to key-value entries, also hiding the heterogeneity of the different PSI algorithms.

We note that the only peculiarity of this interface when compared to the traditional key-store paradigm is that the put
operation should not overwrite a value associated to a key already present. This is required to avoid potential errors
in scenarios where multiple PSI calculations with the same key are initialized concurrently.

Considering that the goal of the cache is to reduce the execution time, reading and writing to the cache should be
computationally cheap compared to encryption operations, whose cost might change based on the specific algorithm and key
size. For testing purposes, in this repository we provide a basic implementation of the
<code>PsiCacheProvider</code> interface based on the <code>ConcurrentHashMap</code> class.

As anticipated, the caching layer can provide performance improvements only when the same keys are used for subsequent
PSI calculations. For instances of the <code>PsiServer</code> class, this can only happen if an external key is provided
to its factory methods (which might also be keys previously generated by the library). Conversely, for instances of
the <code>PsiClient</code> class, the requirements might change based on the specific PSI algorithm. For the BS and ECBS
algorithms, the <code>PsiClient</code> methods can get cache hits even without passing an external key to its factory
methods as long as the public key provided by the <code>PsiServer</code> object is the same as previous executions.
Conversely, for the DH and ECDH algorithms, the methods of the <code>PsiClient</code> class can get cache hits only if
its instance is created by passing to its factory method an external
<code>PsiClientKeyDescription</code> object which was already used in previous executions.

To enable caching during the execution, an object implementing the <code>PsiCacheProvider</code> interface should be
passed to the factory methods that create <code>PsiServer</code> and <code>PsiClient</code> instances.

## Threading

Running encryption operations in parallel on multiple threads can be particularly effective as each portion of data can
be processed independently by each thread with little or no synchronization. To help users exploit the performance
benefits of parallelism, this library supports multi-threading natively. Indeed, all methods that operate on the
datasets split the data in different portions, and each portion is processed by different threads.

By default, all methods that operate on the datasets are executed concurrently on 4 threads. To change this
configuration, as well as to configure the timeout of the threads, the user can call the method
<code>setConfiguration</code> on the <code>PsiServer</code> or <code>PsiClient</code>
instances, passing an instance of a <code>PsiThreadConfiguration</code> with the preferred thread configuration. We note
that the user could set a different number of threads for each method by setting its distinctive
<code>PsiThreadConfiguration</code> object prior to its execution. Despite this internal support, all the classes and methods
of this library are thread-safe, which allows the users of this library to also implement external ad-hoc thread management
techniques.
