# Common.Security.Cryptography

Cryptography should be easy to use and access and provide this capability in a way that is extensible and updatable. Rather than needing to handle and manage resources around the various cryptography implementations, this library provides an alternative to the normal patterns for using cryptographic functions and allows the use of the async/await and dependency injection patterns.

# Security Keys

A `security key` is an entity that is able to provide the requirements of encyption, decryption, signing, and validating signatures. These are backed by strong cryptographic functions such as AES, RSA, and others. 

The security key domain is made up of subdomains of many types of security key. Each subdomain will include the following objects and entities:

`Models`:
 * KeyGenerationParameters
 * KeyExchangeInformation
 * KeyInformation

`Services`:
 * SecurityKeyGenerator
 * SecurityKey

`Dependency Injection`:
 * SecurityKeyDescriptor

The model objects are used by the `SecurityKeyDescriptor`, `ISecurityKeyProvider`, and `SecurityKeyGenerator` to create the security through the points of entry into the library. They act as the gatway to the subdomain and allows the subdomain to be implemented as needed without adding major complexity to the base library. Additionally, generator and allows for clear separation of any necessary initialization tasks from the underlying security key itself.

`KeyInformation` is the central data component that allows the security key to operate, containing the necessary data to construct the key. `KeyExchangeInformation` is the publicly transmittable data that can be sent across the network and then used to reconstruct the required security key on the partner's connection. This provides the ease of use for a consumer of the library by not needing to know what data can/can not be transmitted for secure data transmission.

Additionally, this design should allow the ease of creating and experimenting with new cryptographic algorithms by allowing a simple set of core interfaces and parent models to integrate new security keys into the library for other projects, without needing updates to the main repository -- though updates to strong cryptographic functions or security enhancements to the library in general are welcome!

# Cryptography

The main point of entry into the APIs is via the `ICryptographyService`. In this way, the usage of a broad number of different cryptographic algorithms and related hash functions can be consolidated to one place, providing ease of access. Simply providing the necessary model parameters will generate a usable key for cryptographic purposes. All that should be required to construct the desired security key is simply the parameters desired for the function to operate.

# Available on nuget
https://www.nuget.org/packages/Common.Security.Cryptography#readme-body-tab

# Contributions

Cryptography and data security are important for network and other data management. Feel free to create issues and updates to the library to help it grow and gain access to further security keys.

When creating a branch, please create the branch name using the following format:
`csc-[issue number]-[name]`

There is a workflow that will automatically attach issues to a PR given the format above.
`CSC` is an abbreviation for the library
`Issue number` is the issue that is being addressed by the PR
`Name` is the logical branch name for the work being submitted. While not required, words may be split using `-`. i.e. `csc-5-a-new-branch-fixing-a-terrible-bug` 

When submitting a PR, please include the issue number in the commit title so that it is readable at a glance, i.e. `Fixing a bug (CSC-5)`