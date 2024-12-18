;; Decentralized Identity and Verifiable Credentials Contract
;; Enhanced with additional input validation and security checks

(define-constant ContractOwner tx-sender)
(define-constant ErrorNotAuthorized u1)
(define-constant ErrorIdentityExists u2)
(define-constant ErrorIdentityNotFound u3)
(define-constant ErrorCredentialExists u4)
(define-constant ErrorCredentialNotFound u5)
(define-constant ErrorInvalidCredential u6)
(define-constant ErrorContractPaused u7)
(define-constant ErrorInvalidInput u8)

;; Improved Input validation functions
(define-private (is-valid-did (did (string-ascii 100)))
  (match (slice? did u0 u4)
    prefix (is-eq prefix "did:")
    false
  )
)

(define-private (is-valid-pub-key (pub_key (buff 33)))
  (or 
    (is-eq (len pub_key) u33)
    (is-eq (len pub_key) u65)
  )
)

(define-private (is-valid-metadata (meta_data (string-ascii 500)))
  (and
    (<= (len meta_data) u500)
    (not (is-eq meta_data ""))
  )
)

(define-private (is-valid-cred-id (cred_id (string-ascii 100)))
  (and
    (> (len cred_id) u0)
    (<= (len cred_id) u100)
  )
)

(define-private (is-valid-cred-type (cred_type (string-ascii 50)))
  (and
    (> (len cred_type) u0)
    (<= (len cred_type) u50)
    (or
      (is-eq cred_type "identity")
      (is-eq cred_type "degree")
      (is-eq cred_type "employment")
      (is-eq cred_type "license")
    )
  )
)

(define-private (is-valid-cred-data (cred_data (string-ascii 1000)))
  (<= (len cred_data) u1000)
)

(define-private (is-valid-expiry (expiry (optional uint)))
  (match expiry
    value (> value (get-current-time))
    true))

;; Additional input validation for principals
(define-private (is-valid-principal (user principal))
  (and 
    (not (is-eq user ContractOwner))
    (not (is-eq user tx-sender))
  )
)

;; Data maps for identity and credentials
(define-map IdentityRegistry 
  principal 
  {
    did: (string-ascii 100),
    pub_key: (buff 33),
    meta_data: (string-ascii 500)
  }
)

(define-map CredentialRegistry
  {
    owner: principal,
    cred_id: (string-ascii 100)
  }
  {
    issuer: principal,
    cred_type: (string-ascii 50),
    cred_data: (string-ascii 1000),
    expiry: (optional uint)
  }
)

;; Emergency pause mechanism for contract
(define-data-var contract_paused bool false)

;; Updated pause check function
(define-private (check_not_paused)
  (if (var-get contract_paused)
      (err ErrorContractPaused)
      (ok true))
)

;; Function to get current timestamp (implement based on your blockchain's capabilities)
(define-read-only (get-current-time)
  u0) ;; Placeholder implementation, replace with actual timestamp retrieval

;; Identity Management Functions
(define-public (create_identity 
  (did (string-ascii 100))
  (pub_key (buff 33))
  (meta_data (string-ascii 500))
)
  (begin
    (try! (check_not_paused))
    (asserts! (is-valid-did did) (err ErrorInvalidInput))
    (asserts! (is-valid-pub-key pub_key) (err ErrorInvalidInput))
    (asserts! (is-valid-metadata meta_data) (err ErrorInvalidInput))
    (asserts! (not (is-eq tx-sender ContractOwner)) (err ErrorInvalidInput))
    (match (map-get? IdentityRegistry tx-sender)
      identity (err ErrorIdentityExists)
      (begin 
        (map-set IdentityRegistry 
          tx-sender 
          {
            did: did,
            pub_key: pub_key,
            meta_data: meta_data
          }
        )
        (ok true)
      )
    )
  )
)

(define-public (update_identity_metadata 
  (new_metadata (string-ascii 500))
)
  (begin
    (try! (check_not_paused))
    (asserts! (is-valid-metadata new_metadata) (err ErrorInvalidInput))
    (match (map-get? IdentityRegistry tx-sender)
      current_identity 
        (begin
          (map-set IdentityRegistry 
            tx-sender 
            (merge current_identity { 
              meta_data: new_metadata
            })
          )
          (ok true)
        )
      (err ErrorIdentityNotFound)
    )
  )
)

;; Credential Issuance Functions
(define-public (issue_credential
  (recipient principal)
  (cred_id (string-ascii 100))
  (cred_type (string-ascii 50))
  (cred_data (string-ascii 1000))
  (expiry (optional uint))
)
  (begin
    (try! (check_not_paused))
    (asserts! (is-valid-cred-id cred_id) (err ErrorInvalidInput))
    (asserts! (is-valid-cred-type cred_type) (err ErrorInvalidInput))
    (asserts! (is-valid-cred-data cred_data) (err ErrorInvalidInput))
    (asserts! (is-valid-principal recipient) (err ErrorInvalidInput))
    (asserts! (is-valid-expiry expiry) (err ErrorInvalidInput))
    (match (map-get? IdentityRegistry recipient)
      identity 
        (match (map-get? CredentialRegistry { 
                  owner: recipient, 
                  cred_id: cred_id 
                })
          existing_cred (err ErrorCredentialExists)
          (begin
            (map-set CredentialRegistry
              {
                owner: recipient,
                cred_id: cred_id
              }
              {
                issuer: tx-sender,
                cred_type: cred_type,
                cred_data: cred_data,
                expiry: expiry
              }
            )
            (ok true)
          )
        )
      (err ErrorIdentityNotFound)
    )
  )
)

;; Credential Verification Functions
(define-read-only (verify_credential
  (identity_owner principal)
  (cred_id (string-ascii 100))
)
  (match (map-get? CredentialRegistry { 
    owner: identity_owner, 
    cred_id: cred_id 
  })
    cred 
      (match (get expiry cred)
        expiry-value (if (> expiry-value (get-current-time))
                         (some cred)
                         none)
        (some cred))
    none
  )
)

;; Revocation of Credentials
(define-public (revoke_credential
  (recipient principal)
  (cred_id (string-ascii 100))
)
  (begin
    (try! (check_not_paused))
    (asserts! (is-valid-cred-id cred_id) (err ErrorInvalidInput))
    (asserts! (is-valid-principal recipient) (err ErrorInvalidInput))
    (match (map-get? CredentialRegistry { 
              owner: recipient, 
              cred_id: cred_id 
            })
      credential 
        (if (is-eq (get issuer credential) tx-sender)
            (begin
              (map-delete CredentialRegistry { 
                owner: recipient, 
                cred_id: cred_id 
              })
              (ok true)
            )
            (err ErrorNotAuthorized))
      (err ErrorCredentialNotFound)
    )
  )
)

;; Improved helper read-only function to check if an identity exists
(define-read-only (identity_exists (user principal))
  (and 
    (is-some (map-get? IdentityRegistry user))
    (is-valid-principal user)
  )
)

;; Emergency pause mechanism for contract
(define-public (toggle_contract_pause)
  (begin
    (asserts! (is-eq tx-sender ContractOwner) (err ErrorNotAuthorized))
    (ok (var-set contract_paused (not (var-get contract_paused))))
  )
)

