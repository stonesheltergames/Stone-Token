//pragma solidity 0.8.0;
//SPDX-License-Identifier: UNLICENSED
    
interface IBEP20 {
    /**
    * @dev Returns the amount of tokens in existence.
    */
    function totalSupply() external view returns (uint256);
    
    /**
    * @dev Returns the token decimals.
    */
    function decimals() external view returns (uint8);
    
    /**
    * @dev Returns the token symbol.
    */
    function symbol() external view returns (string memory);
    
    /**
    * @dev Returns the token name.
    */
    function name() external view returns (string memory);
    
    /**
    * @dev Returns the bep token owner.
    */
    function getOwner() external view returns (address);
    
    /**
    * @dev Returns the amount of tokens owned by `account`.
    */
    function balanceOf(address account) external view returns (uint256);
    
    /**
    * @dev Moves `amount` tokens from the caller's account to `recipient`.
    *
    * Returns a boolean value indicating whether the operation succeeded.
    *
    * Emits a {Transfer} event.
    */
    function transfer(address recipient, uint256 amount) external returns (bool);
    
    /**
    * @dev Returns the remaining number of tokens that `spender` will be
    * allowed to spend on behalf of `owner` through {transferFrom}. This is
    * zero by default.
    *
    * This value changes when {approve} or {transferFrom} are called.
    */
    function allowance(address _owner, address spender) external view returns (uint256);
    
    /**
    * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
    *
    * Returns a boolean value indicating whether the operation succeeded.
    *
    * IMPORTANT: Beware that changing an allowance with this method brings the risk
    * that someone may use both the old and the new allowance by unfortunate
    * transaction ordering. One possible solution to mitigate this race
    * condition is to first reduce the spender's allowance to 0 and set the
    * desired value afterwards:
    * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
    *
    * Emits an {Approval} event.
    */
    function approve(address spender, uint256 amount) external returns (bool);
    
    /**
    * @dev Moves `amount` tokens from `sender` to `recipient` using the
    * allowance mechanism. `amount` is then deducted from the caller's
    * allowance.
    *
    * Returns a boolean value indicating whether the operation succeeded.
    *
    * Emits a {Transfer} event.
    */
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    
    /**
    * @dev Emitted when `value` tokens are moved from one account (`from`) to
    * another (`to`).
    *
    * Note that `value` may be zero.
    */
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    /**
    * @dev Emitted when the allowance of a `spender` for an `owner` is set by
    * a call to {approve}. `value` is the new allowance.
    */
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

/**
 * @dev Multiple administrators interface:
 * - Checks requiring all administrators to sign N times before executing functions
 * - Alive signatures: in case an admin does not execute any functions in X days they will be removed from admins, this is to avoid locking the signatures
 */
abstract contract Administrable{
    uint256 constant adminExpiration = 60 days;             // Time after which an admin is marked as inactive if it does not execute any function
    uint256 constant signatureExpiration = 5 minutes;       // Duration of an admin signature, after which it will expire and will need to be signed again
    uint256 constant signatureSetExpiration = 10 minutes;   // Duration of an admins signature set, after which it will expire and will need to be validated again
    
    mapping (address => bool) private adminsMap;
    address[] internal adminsList;
    mapping (address => uint256) private adminsLastActivity;
    mapping (address => uint256) private adminsSignatures;
    uint8 adminsSignaturesSets = 0;             // Times all the admins signed together, this is used for stronger actions which require all the admins signing together twice, three times, ...
    uint256 adminsSignaturesSetsCreation = 0;   // Time at which the last signature set was created
    
    bool _contractLocked = false;
    
    event AddedAdministrator(address indexed admin);    // Called when a new admin is nominated
    event RemovedAdministrator(address indexed admin);  // Called when an admin is removed


    /**
     * @dev Add the contract creator as the first admin
     */
    constructor (){
        _addAdmin(msg.sender);
    }
    
    /**
     * @dev Returns true if the contract is locked and cannot be interacted with
     */
    function isLocked() external view returns (bool){
        return _contractLocked;
    }
    
    modifier notLocked(){
        require(!_contractLocked, "Administrable: contract locked");
        _;
    }
    
    /**
     * @dev Returns the addresses of the current admins.
     */
    function admins() public view returns (address[] memory){
        return adminsList;
    }
    
    /**
     * @dev Returns the number of current admins.
     */
    function adminsNumber() public view returns (uint){
        return adminsList.length;
    }
    
    /**
     * @dev Checks if a given user is an admin
     */
    function isAdmin(address user) public view returns (bool){
        return adminsMap[user];
    }
    
    /**
     * @dev Adds an admin to the list and the map
     */
    function _addAdmin(address user) internal{
        adminsList.push(user);
        adminsMap[user] = true;
        adminsLastActivity[user] = block.timestamp;
        emit AddedAdministrator(user);
    }
    
    /**
     * @dev Removes an admin from the list and the map
     */
    function _removeAdmin(address admin) internal{
        // Delete the admin from the map
        adminsMap[admin] = false;
        
        // Delete the admin from the list
        for(uint i = 0; i < adminsList.length; i++){
            if(adminsList[i] == admin){
                // Copy the last key to the current and shorten the array length by one
                adminsList[i] = adminsList[adminsList.length-1];
                adminsList.pop();
                emit RemovedAdministrator(admin);
                return;
            }
        }
    }
    
    /**
     * @dev Throws if called by any account other than admins, also updates last activity at the end
     */
    modifier requireAdmin(){
        // Check if the user is an admin
        require(isAdmin(msg.sender), "Administrable: caller is not an admin");
        
        // Execute function
        _;
        
        // Update last activity to now
        adminsLastActivity[msg.sender] = block.timestamp;
    }
    
    /**
     * @dev Returns the number of times the admins signed together
     */
    function adminSignatureSets() public view returns (uint){
        return adminsSignaturesSets;
    }
    
    /**
     * @dev Deletes all the signatures
     */
    function _resetSignatures() internal{
        // Reset all the signatures
        for(uint i = 0; i < adminsList.length; i++){
            adminsSignatures[adminsList[i]] = 0;
        }
    }
    
    /**
     * @dev Deletes all the signatures and resets any previous sets
     */
    function _resetSignaturesAndSets() internal{
        // Reset the sets
        adminsSignaturesSets = 0;
        
        // Reset all the signatures
        _resetSignatures();
    }
    
    /**
     * @dev Puts an admin signature to allow calling function requiring all admins signatures
     */
    function adminSign() public notLocked requireAdmin{
        // Check if the admin already signed
        require(adminsSignatures[msg.sender] < block.timestamp - signatureExpiration, "Administrable: the admin already signed");
        
        // Update the signature
        adminsSignatures[msg.sender] = block.timestamp;
    }
    
    /**
     * @dev Checks if all admins signed
     */
    function _checkSignatures() internal view{
        for(uint i = 0; i < adminsList.length; i++){
            require(adminsSignatures[adminsList[i]] >= block.timestamp - signatureExpiration, "Administrable: not all admins signed or some signatures expired");
        }
    }
    
    /**
     * @dev Checks all the admins signatures and creates a new set if all valid, this should be called when more than 1 set is needed
     */
    function adminValidateSignatures() public notLocked requireAdmin{
        // Check all the admin signatures
        _checkSignatures();
        
        // Check that the previous set has not expired (if any), and update time
        if(adminsSignaturesSets > 0 && adminsSignaturesSetsCreation < block.timestamp - signatureSetExpiration)
            adminsSignaturesSets = 1;
        else
            adminsSignaturesSets++;
        adminsSignaturesSetsCreation = block.timestamp;
        
        // Reset the signatures, to allow signing again
        _resetSignatures();
    }
    
    /**
     * @dev Throws if there are admin signatures or sets missing
     */
    modifier requireAdminSignatureSets(uint sets){
        // Check if any previous signature sets expired
        require(sets == 1 || (adminsSignaturesSets >= sets-1 && adminsSignaturesSetsCreation >= block.timestamp - signatureSetExpiration), "Administrable: missing signature sets or expired signature sets");
        
        // If we are missing a signature set check all the admin signatures
        if(adminsSignaturesSets == sets-1)
            _checkSignatures();
        
        // Execute function
        _;
        
        // Reset the signatures and sets
        _resetSignaturesAndSets();
    }
    
    /**
     * @dev Add a new admin
     */
    function addAdmin(address user) public notLocked requireAdmin requireAdminSignatureSets(1){
        _addAdmin(user);
    }
    
    /**
     * @dev Remove an existing admin, this checks for admin signatures excluding inactive admins, this prevents getting stuck if some admin lost access to their keys
     */
    function removeAdmin(address admin) public notLocked requireAdmin{
        // Check all the admin signatures, except the expired ones
        for(uint i = 0; i < adminsList.length; i++){
            require(adminsLastActivity[adminsList[i]] < block.timestamp - adminExpiration || adminsSignatures[adminsList[i]] >= block.timestamp - signatureExpiration, "Administrable: not all admins signed or some signatures expired");
        }
        
        _removeAdmin(admin);
        
        // Reset the signatures and sets
        _resetSignaturesAndSets();
    }
    
    /**
     * @dev Permanently disables the contract, leaving only read-only interactions available
     */
    function lockContract() public notLocked requireAdmin requireAdminSignatureSets(3){
        _contractLocked = true;
    }
}

contract StoneToken is IBEP20, Administrable {
  mapping (address => uint256) private _balances;

  mapping (address => mapping (address => uint256)) private _allowances;

  uint256 private _totalSupply;
  uint8 private _decimals;
  string private _symbol;
  string private _name;
  
  bool private _canMint = true;

  constructor() {
    _name = "Stone Token";
    _symbol = "STONE";
    _decimals = 2;
    _totalSupply = 0;
  }

  /**
   * @dev Returns the bep token owner.
   */
  function getOwner() override external view returns (address) {
    // The named owner will be the first admin, this is required by the BEP-20 standard
    return admins()[0];
  }

  /**
   * @dev Returns the token decimals.
   */
  function decimals() override external view returns (uint8) {
    return _decimals;
  }

  /**
   * @dev Returns the token symbol.
   */
  function symbol() override external view returns (string memory) {
    return _symbol;
  }

  /**
  * @dev Returns the token name.
  */
  function name() override external view returns (string memory) {
    return _name;
  }

  /**
   * @dev See {BEP20-totalSupply}.
   */
  function totalSupply() override external view returns (uint256) {
    return _totalSupply;
  }

  /**
   * @dev See {BEP20-balanceOf}.
   */
  function balanceOf(address account) override external view returns (uint256) {
    return _balances[account];
  }

  /**
   * @dev See {BEP20-transfer}.
   *
   * Requirements:
   *
   * - `recipient` cannot be the zero address.
   * - the caller must have a balance of at least `amount`.
   */
  function transfer(address recipient, uint256 amount) override external notLocked returns (bool) {
    _transfer(msg.sender, recipient, amount);
    return true;
  }

  /**
   * @dev See {BEP20-allowance}.
   */
  function allowance(address owner, address spender) override external view returns (uint256) {
    return _allowances[owner][spender];
  }

  /**
   * @dev See {BEP20-approve}.
   *
   * Requirements:
   *
   * - `spender` cannot be the zero address.
   */
  function approve(address spender, uint256 amount) override external notLocked returns (bool) {
    _approve(msg.sender, spender, amount);
    return true;
  }

  /**
   * @dev See {BEP20-transferFrom}.
   *
   * Emits an {Approval} event indicating the updated allowance. This is not
   * required by the EIP. See the note at the beginning of {BEP20};
   *
   * Requirements:
   * - `sender` and `recipient` cannot be the zero address.
   * - `sender` must have a balance of at least `amount`.
   * - the caller must have allowance for `sender`'s tokens of at least
   * `amount`.
   */
  function transferFrom(address sender, address recipient, uint256 amount) override external notLocked returns (bool) {
    _transfer(sender, recipient, amount);
    require(_allowances[sender][msg.sender] >= amount, "BEP20: transfer amount exceeds allowance");
    _approve(sender, msg.sender, _allowances[sender][msg.sender] - amount);
    return true;
  }

  /**
   * @dev Atomically increases the allowance granted to `spender` by the caller.
   *
   * This is an alternative to {approve} that can be used as a mitigation for
   * problems described in {BEP20-approve}.
   *
   * Emits an {Approval} event indicating the updated allowance.
   *
   * Requirements:
   *
   * - `spender` cannot be the zero address.
   */
  function increaseAllowance(address spender, uint256 addedValue) public notLocked returns (bool) {
    _approve(msg.sender, spender, _allowances[msg.sender][spender] + addedValue);
    return true;
  }

  /**
   * @dev Atomically decreases the allowance granted to `spender` by the caller.
   *
   * This is an alternative to {approve} that can be used as a mitigation for
   * problems described in {BEP20-approve}.
   *
   * Emits an {Approval} event indicating the updated allowance.
   *
   * Requirements:
   *
   * - `spender` cannot be the zero address.
   * - `spender` must have allowance for the caller of at least
   * `subtractedValue`.
   */
  function decreaseAllowance(address spender, uint256 subtractedValue) public notLocked returns (bool) {
    _approve(msg.sender, spender, _allowances[msg.sender][spender] - subtractedValue);
    return true;
  }
  
  /**
   * @dev Returns true if more tokens can be minted, false if it is locked
   */
  function canMint() external view returns (bool){
      return _canMint;
  }
  
  /**
   * @dev Permanently disables minting of new token
   */
  function disableMinting() external notLocked requireAdmin requireAdminSignatureSets(2){
      _canMint = false;
  }
  
  /**
   * @dev Creates `amount` tokens and assigns them to `recipient`, increasing
   * the total supply. This requires 1 signature set from admins
   */
  function mint(address recipient, uint256 amount) public notLocked requireAdmin requireAdminSignatureSets(1) returns (bool) {
    require(_canMint, "Token minting locked");
    _mint(recipient, amount);
    return true;
  }
  
  /**
   * @dev Burns `amount` tokens from `msg.sender`
   */
  function burn(uint256 amount) public notLocked returns (bool){
      _burn(msg.sender, amount);
      return true;
  }

  /**
   * @dev Moves tokens `amount` from `sender` to `recipient`.
   *
   * This is internal function is equivalent to {transfer}, and can be used to
   * e.g. implement automatic token fees, slashing mechanisms, etc.
   *
   * Emits a {Transfer} event.
   *
   * Requirements:
   *
   * - `sender` cannot be the zero address.
   * - `recipient` cannot be the zero address.
   * - `sender` must have a balance of at least `amount`.
   */
  function _transfer(address sender, address recipient, uint256 amount) internal {
    require(sender != address(0), "BEP20: transfer from the zero address");
    require(recipient != address(0), "BEP20: transfer to the zero address");
    
    require(_balances[sender] >= amount, "BEP20: transfer amount exceeds balance");
    _balances[sender] = _balances[sender] - amount;
    _balances[recipient] = _balances[recipient] + amount;
    emit Transfer(sender, recipient, amount);
  }

  /** @dev Creates `amount` tokens and assigns them to `account`, increasing
   * the total supply.
   *
   * Emits a {Transfer} event with `from` set to the zero address.
   *
   * Requirements
   *
   * - `to` cannot be the zero address.
   */
  function _mint(address account, uint256 amount) internal {
    require(account != address(0), "BEP20: mint to the zero address");

    _totalSupply = _totalSupply + amount;
    _balances[account] = _balances[account] + amount;
    emit Transfer(address(0), account, amount);
  }

  /**
   * @dev Destroys `amount` tokens from `account`, reducing the
   * total supply.
   *
   * Emits a {Transfer} event with `to` set to the zero address.
   *
   * Requirements
   *
   * - `account` cannot be the zero address.
   * - `account` must have at least `amount` tokens.
   */
  function _burn(address account, uint256 amount) internal {
    require(account != address(0), "BEP20: burn from the zero address");

    require(_balances[account] >= amount, "BEP20: burn amount exceeds balance");
    _balances[account] = _balances[account] - amount;
    _totalSupply = _totalSupply - amount;
    emit Transfer(account, address(0), amount);
  }

  /**
   * @dev Sets `amount` as the allowance of `spender` over the `owner`s tokens.
   *
   * This is internal function is equivalent to `approve`, and can be used to
   * e.g. set automatic allowances for certain subsystems, etc.
   *
   * Emits an {Approval} event.
   *
   * Requirements:
   *
   * - `owner` cannot be the zero address.
   * - `spender` cannot be the zero address.
   */
  function _approve(address owner, address spender, uint256 amount) internal {
    require(owner != address(0), "BEP20: approve from the zero address");
    require(spender != address(0), "BEP20: approve to the zero address");

    _allowances[owner][spender] = amount;
    emit Approval(owner, spender, amount);
  }
}