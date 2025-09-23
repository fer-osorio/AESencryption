#ifndef CIPHER_HPP
#define CIPHER_HPP

#include"key.hpp"
#include"encryptor.hpp"

namespace AESencryption {

// Forward declarations of custom exceptions
class AESException;
class KeyExpansionException;
class EncryptionException;
class DecryptionException;

struct InitVector;

std::ostream& operator << (std::ostream& st, const Cipher& c);			// -Declaration here so this function is inside the name space function.

class Cipher : public Encryptor {
public:
	struct OperationMode{
	public:
		enum struct Identifier {
			Unknown,
			ECB,							// -Electronic Code Book (not recommended).
			CBC,							// -Cipher Block Chaining.
		};
	private:
		Identifier ID_ = Identifier::ECB;
		InitVector* IV_ = nullptr;						// -Initial vector in case of CBC operation mode
	public:
		OperationMode();
		OperationMode(Identifier);
		OperationMode(const OperationMode&);
		OperationMode& operator=(const OperationMode&);
		~OperationMode();

		static OperationMode buildInCBCmode(const InitVector& IVsource);

		Identifier getOperationModeID() const;
		const uint8_t* getIVpointerData() const;
	};
	struct Config{
	private:
		OperationMode operationMode;
		size_t Nk_;
		size_t Nr;
		size_t keyExpansionLengthBytes;
	public:
		Config();
		Config(OperationMode optMode, Key::LengthBits);
		OperationMode::Identifier getOperationModeID() const;
		size_t getNk() const;
		size_t getNr() const;
		size_t getKeyExpansionLengthBytes() const;
		const uint8_t* getIVpointerData() const;
	};
private:
	Key key = Key();
	uint8_t* keyExpansion = nullptr;
	struct Config config;

	Cipher();								// -The default constructor will set the key expansion as zero in every element.

public:
	Cipher(const Key&, const OperationMode::Identifier);
	Cipher(const Cipher& a);
	~Cipher();

	Cipher& operator = (const Cipher& a);
	friend std::ostream& operator << (std::ostream& st, const Cipher& c);

	/*
	 * Encrypts data contatined in data vector using the key in cipher this object
	 * Interface with Encryptor object
	 * Consider: Throws std::invalid_argument, EncryptionException, AESException
	 * */
	void encryption(const std::vector<uint8_t>& input, std::vector<uint8_t>& output) const override;

	/*
	 * Decrypts data contatined in data vector using the key in cipher this object
	 * Interface with Encryptor object
	 * Consider: Throws std::invalid_argument, EncryptionException, AESException
	 * */
	void decryption(const std::vector<uint8_t>& input, std::vector<uint8_t>& output) const override;

		/*
	 * Encrypts using operation mode stored in Cipher object
	 * Consider: Comunicates with AES.h
	 * Consider: Rewrites bytes pointed by output
	 * Consider: Throws std::invalid_argument, EncryptionException, AESException
	 * */
	void encrypt(const uint8_t*const data, size_t size, uint8_t*const output)const;

	/*
	 * Decrypts using operation mode stored in Cipher object
	 * Consider: Comunicates with AES.h
	 * Consider: Rewrites bytes pointed by output
	 * Consider: Throws std::invalid_argument, EncryptionException, AESException
	 * */
	void decrypt(const uint8_t*const data, size_t size, uint8_t*const output)const;


	void saveKey(const char*const fname) const;
	OperationMode getOptModeID() const;

	// For testing purposes
	const uint8_t* getKeyExpansionForTesting() const;
	bool isKeyExpansionInitialized() const;
	const uint8_t* getInitialVectorForTesting() const;

	private:
	OperationMode buildOperationMode(const OperationMode::Identifier);
	/*
	 * Creates key expansion
	 * Consider: Trows KeyExpansionException
	 * */
	void buildKeyExpansion();
	void formInitialVector();						// -Creates initial vector and writes it on destination array
};
};
#endif