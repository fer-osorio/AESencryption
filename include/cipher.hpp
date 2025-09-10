#ifndef CIPHER_HPP
#define CIPHER_HPP

#include"key.hpp"
#include"encryptor.hpp"

namespace AESencryption {

struct InitVector;

std::ostream& operator << (std::ostream& st, const Cipher& c);			// -Declaration here so this function is inside the name space function.

class Cipher : public Encryptor {
public:
	struct OperationMode{
	public:
		enum struct Identifier {
			ECB,							// -Electronic Code Book (not recommended).
			CBC,							// -Cipher Block Chaining.
		};
	private:
		Identifier ID_ = Identifier::ECB;
		InitVector* IV_ = NULL;						// -Initial vector in case of CBC operation mode
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
		Config(OperationMode optMode, size_t Nk);
		OperationMode::Identifier getOperationModeID() const;
		size_t getNk() const;
		size_t getNr() const;
		size_t getKeyExpansionLengthBytes() const;
		const uint8_t* getIVpointerData() const;
	};
private:
	Key key = Key();
	uint8_t* keyExpansion = NULL;
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
	 * */
	void encryption(std::vector<uint8_t>& data) const override;

	/*
	 * Decrypts data contatined in data vector using the key in cipher this object
	 * Interface with Encryptor object
	 * */
	void decryption(std::vector<uint8_t>& data) const override;

	void saveKey(const char*const fname) const;
	OperationMode getOptModeID() const;

	private:
	OperationMode buildOperationMode(const OperationMode::Identifier);
	void buildKeyExpansion();						// -Creates key expansion
	void formInitialVector();						// -Creates initial vector and writes it on destination array

	/*
	 * Encrypts using operation mode stored in Cipher object
	 * Consider: Comunicates with AES.h
	 * */
	void encrypt(const uint8_t*const data, size_t size, uint8_t*const output)const;

	/*
	 * Decrypts using operation mode stored in Cipher object
	 * Consider: Comunicates with AES.h
	 * */
	void decrypt(const uint8_t*const data, size_t size, uint8_t*const output)const;
};
};
#endif