;; Decentralized Identity and Verifiable Credentials Contract
;; This contract provides a comprehensive system for:
;; 1. User-controlled decentralized identity
;; 2. Credential issuance and verification
;; 3. Secure, privacy-preserving credential management

(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-NOT-AUTHORIZED u1)
(define-constant ERR-IDENTITY-EXISTS u2)
(define-constant ERR-IDENTITY-NOT-FOUND u3)
(define-constant ERR-CREDENTIAL-EXISTS u4)
(define-constant ERR-CREDENTIAL-NOT-FOUND u5)
(define-constant ERR-INVALID-CREDENTIAL u6)
(define-constant ERR-CONTRACT-PAUSED u7)

;; Data maps for identity and credentials
(define-map identities 
  principal 
  {
    did: (string-ascii 100),
    public-key: (buff 33),
    created-at: uint,
    metadata: (string-ascii 500)
  }
)

(define-map credentials
  {
    identity: principal,
    credential-id: (string-ascii 100)
  }
  {
    issuer: principal,
    credential-type: (string-ascii 50),
    data: (string-ascii 1000),
    issued-at: uint,
    expires-at: (optional uint)
  }
)

;; Emergency pause mechanism for contract
(define-data-var contract-paused bool false)

;; Pause check modifier
(define-private (check-not-paused)
  (if (var-get contract-paused)
      (err ERR-CONTRACT-PAUSED)
      (ok true)
  )
)

;; Identity Management Functions
(define-public (create-identity 
  (did (string-ascii 100))
  (public-key (buff 33))
  (metadata (string-ascii 500))
)
  (begin
    (try! (check-not-paused))
    (if (is-none (map-get? identities tx-sender))
        (begin 
          (map-set identities 
            tx-sender 
            {
              did: did,
              public-key: public-key,
              created-at: (get-block-height),
              metadata: metadata
            }
          )
          (ok true)
        )
        (err ERR-IDENTITY-EXISTS)
    )
  )
)

(define-public (update-identity-metadata 
  (new-metadata (string-ascii 500))
)
  (begin
    (try! (check-not-paused))
    (match (map-get? identities tx-sender)
      current-identity 
        (begin
          (map-set identities 
            tx-sender 
            (merge current-identity { metadata: new-metadata })
          )
          (ok true)
        )
      (err ERR-IDENTITY-NOT-FOUND)
    )
  )
)

;; Credential Issuance Functions
(define-public (issue-credential
  (recipient principal)
  (credential-id (string-ascii 100))
  (credential-type (string-ascii 50))
  (credential-data (string-ascii 1000))
  (expiration (optional uint))
)
  (begin
    (try! (check-not-paused))
    (match (map-get? identities recipient)
      identity 
        (match (map-get? credentials { 
                  identity: recipient, 
                  credential-id: credential-id 
                })
          existing-cred (err ERR-CREDENTIAL-EXISTS)
          (begin
            (map-set credentials
              {
                identity: recipient,
                credential-id: credential-id
              }
              {
                issuer: tx-sender,
                credential-type: credential-type,
                data: credential-data,
                issued-at: (get-block-height),
                expires-at: expiration
              }
            )
            (ok true)
          )
        )
      (err ERR-IDENTITY-NOT-FOUND)
    )
  )
)

;; Credential Verification Functions
(define-read-only (verify-credential
  (identity principal)
  (credential-id (string-ascii 100))
)
  (let ((credential 
          (map-get? credentials { 
            identity: identity, 
            credential-id: credential-id 
          })
        ))
    (match credential
      cred 
        (if (or 
              (is-none (get expires-at cred))
              (< (get-block-height) (unwrap-panic (get expires-at cred)))
            )
            (some cred)
            none
        )
      none
    )
  )
)

;; Revocation of Credentials
(define-public (revoke-credential
  (recipient principal)
  (credential-id (string-ascii 100))
)
  (begin
    (try! (check-not-paused))
    (match (map-get? credentials { 
              identity: recipient, 
              credential-id: credential-id 
            })
      credential 
        (if (is-eq (get issuer credential) tx-sender)
            (begin
              (map-delete credentials { 
                identity: recipient, 
                credential-id: credential-id 
              })
              (ok true)
            )
            (err ERR-NOT-AUTHORIZED)
        )
      (err ERR-CREDENTIAL-NOT-FOUND)
    )
  )
)

;; Helper read-only function to check if an identity exists
(define-read-only (identity-exists (user principal))
  (is-some (map-get? identities user))
)

;; Emergency pause mechanism for contract
(define-public (toggle-contract-pause)
  (begin
    (if (is-eq tx-sender CONTRACT-OWNER)
        (begin
          (var-set contract-paused (not (var-get contract-paused)))
          (ok (var-get contract-paused))
        )
        (err ERR-NOT-AUTHORIZED)
    )
  )
)

