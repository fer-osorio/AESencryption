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
		Identifier ID_;
		InitVector* IV_ = NULL;						// -Initial vector in case of CBC operation mode

	public:
		OperationMode(Identifier);
		OperationMode(const OperationMode&);
		OperationMode& operator=(const OperationMode&);
		~OperationMode();
		Identifier getOperationModeID() const;
		const uint8_t* getIVpointerData() const;

	};
	struct Config{
	private:
		OperationMode operationMode;
		size_t _Nk;
		size_t Nr;
		size_t keyExpansionLengthBytes;
	public:
		Config(OperationMode::Identifier opModeID, size_t Nk);
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

	void encryption(std::vector<uint8_t>& data) const override;
	void decryption(std::vector<uint8_t>& data) const override;

	void saveKey(const char*const fname) const;
	OperationMode getOptModeID() const;

	private:
	/*
	void set_IV(const InitVector source);					// -Sets initial vector by copying the array passed as argument
	bool IVisInitialized() const { return this->initializedIV; }
	*/
	void buildKeyExpansion();						// -Creates key expansion
	void formInitialVector();						// -Creates initial vector and writes it on destination array
	void encrypt(const uint8_t*const data, size_t size, uint8_t*const output)const;	// -Encrypts using operation mode stored in Key object
	void decrypt(const uint8_t*const data, size_t size, uint8_t*const output)const;	// -Decrypts using operation mode stored in Key object
};
};
#endif