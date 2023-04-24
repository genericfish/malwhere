const TokenType = {
    Break: "Break",
    Comment: "Comment",
    Field: "Field",
    FuncName: "FuncName",
    Label: "Label",
    Op: "Op",
    Syntax: "Syntax",
    Type: "Type",
    Variable: "Variable",
}

const TokenProperty = {
    Type: 'Type',
    Value: 'Value',
    DataType: 'DataType'
}

/**
 * Defines manner of which a Ghidra token will be modified
 */
const Replacement = {
    Keep: _ => token => token,
    Drop: _ => _ => null,
    Modify: (prop, ...rest) => {
        switch (prop) {
            case TokenProperty.Type:
                if (!(rest[0] in TokenType))
                throw "TokenReplacement.Modify(TokenProperty.Type, TokenType) invalid TokenType"
                
                return token => {
                    token.type = token
                    
                    return token
                }
                case TokenProperty.Value:
                    if (rest[0]?.constructor === RegExp) {
                        return token => {
                            token.value = token.value.replace(rest[0], rest[1])

                            return token
                        }
                    } else if (rest[0]?.constructor === String) {
                        return token => {
                            token.value = rest[0]

                            return token
                        }
                    }

                throw "TokenReplacement.Modify(TokenProperty.Value, RegExp | String) expected second argument to be RegExp or String"
            case TokenProperty.DataType:
                return token => {
                    token.dataType = rest[0]

                    return token
                }
            default:
                throw "Replacement.Modify(*) expected valid TokenProperty"
        }
    },
    Expand: (...tokens) => _ => tokens,
    Custom: callback => ghidraToken => callback(ghidraToken)
}

/**
 * Token expressions match against exported Ghidra tokens
 */
class TokenExp {
    constructor (type, value, dataTypeOrReplace=null, replace=null) {
        this.type = type
        this.value = value

        this.replace = replace
        if (typeof dataTypeOrReplace === "function") {
            this.replace = dataTypeOrReplace
        } else if (type === TokenType.Variable && dataTypeOrReplace?.constructor === "") {
            this.dataType = dataTypeOrReplace
        }

        if (!this.replace)
            this.replace = Replacement.Keep()

        Object.freeze(this)
    }

    match(ghidraToken) {
        if (ghidraToken?.type != this.type)
            return false

        if (!ghidraToken?.value?.match(this.value))
            return false

        if (this.dataType)
            return ghidraToken?.data_type?.match(this.dataType)

        return true
    }
}

/**
 * Rules describe compositions of other rules or token expressions (not both at the same time)
 * 
 * A rule composed of token expressions is called terminal.
 * 
 * A terminal rule matches a parser token stream if and only if
 * all token expressions match the token stream in the same order as they appear.
 * 
 * A rule composed of other rules is called non-terminal.
 *
 * A non-terminal rule matches a parser token stream if
 * there exists a terminal sub-rule that matches.
 */
class Rule {
    constructor (name, ...ruleLike) {
        const sameType = ruleLike
                            .map(e => e?.constructor)
                            .every((e, _, a) => e === a[0] && (e === Rule || e === TokenExp))

        if (!sameType)
            throw "Rule expected all arguments to be of same type (Rule or Token)"

        this.name = name
        this.pattern = ruleLike
        this.type = this.pattern[0].constructor

        this.optional = new OptionalRule(this)

        Object.freeze(this)
    }

    get length() {
        return this.pattern.length
    }
}

/**
 * OptionalRules are the same as Rules but do not need to be matched inside a Statement.
 */
class OptionalRule {
    constructor (rule) {
        // TODO: Would extending Rule make more sense?
        if (rule.constructor !== Rule)
            throw "OptionalRule constructor expected Rule"

        // Give OptionalRule same properties as Rule, save for 'optional'
        const {optional: _, ...properties} = rule
        Object.assign(this, properties)

        this.name = "optional_" + this.name
        this.required = rule

        Object.freeze(this)
    }
}

/**
 * Statements describe compositions of rules.
 */
class Statement {
    constructor (name, ...rules) {
        const sameType = rules
                            .map(e => e?.constructor)
                            .every(e => e === Rule || e === OptionalRule)

        if (!sameType)
            throw "Statement expected all arguments to be of type Rule"

        this.name = name
        this.rules = rules
        this.numRequiredRules = rules.reduce((acc, rule) => acc + (rule.constructor === Rule), 0)

        Object.freeze(this)
    }
}

/**
 * Groups contain the matched Ghidra tokens for a given Rule.
 */
class Group {
    constructor (rule, tokens) {
        this.rule = rule
        this.tokens = tokens

        Object.freeze(this)
    }

    replace() {
        const replaced = this.tokens.map((ghidraToken, i) => this.rule.pattern[i].replace(ghidraToken)).filter(v => v)
        return new Group(this.rule, replaced)
    }

    toString() {
        return this.tokens.map(token => token.value).join('')
    }

    get name() {
        return this.rule.name
    }

    get length() {
        return this.tokens.length
    }
}

/**
 * Container for Groups.
 */
class MatchResults {
    constructor (groups) {
        this.groups = groups
    }

    find(rule) {
        if (rule.type === Rule) {
            for (const subrule of rule.pattern) {
                const result = this.find(subrule)

                if (this.find(subrule))
                    return result
            }
        }

        return this.groups.find(group => group.rule === rule)
    }

    reorder(...rules) {
        const ordered = rules.map(rule => this.find(rule)).filter(v => v)

        return new MatchResults(ordered)
    }

    replace() {
        const replaced = this.groups.map(group => group.replace())

        return new MatchResults(replaced)
    }

    toString() {
        return this.groups.map(group => String(group)).join('')
    }
}

/**
 * Magic.
 */
class Parser {
    constructor (ghidraTokens, skipEmpty=false, skipComments=false) {
        this.tokens = ghidraTokens
        this.cursor = 0
        this.skipEmpty = skipEmpty
        this.skipComments = skipComments

        if (skipEmpty)
            this.tokens = this.tokens.filter(token => token.type !== TokenType.Break && token.value.trim().length)

        if (skipComments)
            this.tokens = this.tokens.filter(token => token.type !== TokenType.Comment)

        this._stmt_end_token = new TokenExp(TokenType.Syntax, /^[;|{|}]/)
    }

    match(statementLike) {
        let result = null

        if (statementLike.constructor === Rule)
            result = this.#matchRule(statementLike)
        else if (statementLike.constructor === Statement)
            result = this.#matchStatement(statementLike)

        return result
    }

    #matchStatement(stmt) {
        if (this.length < stmt.numRequiredRules)
            return null

        // Define custom cursor so as to not modify state of parser
        const numRules = stmt.rules.length

        let i = 0
        let groups = []
        let closeStatement = false

        for (let cursor = 0; i < numRules && this.peek(cursor); cursor++) {
            const rule = stmt.rules[i]
            const match = this.#matchRule(rule, cursor)

            if (match) {
                cursor += rule.length +1
                groups.push(match)

                i++
            }

            if (closeStatement)
                return

            closeStatement = this.statementEnd(cursor)
        }

        if (i < stmt.numRequiredRules)
            return null

        return new MatchResults(groups)
    }

    #matchRule(rule, n=0) {
        if (rule.type === Rule)
            return rule.pattern.reduce((acc, rule) => acc ?? this.#matchRule(rule, n), null)

        if (!this.peek(n + rule.length))
            return null

        let matchedTokens = []
        for (const [i, token] of rule.pattern.entries()) {
            const lookAhead = this.peek(n + i)

            if (!token.match(lookAhead))
                return null

            matchedTokens.push(lookAhead)
        }

        return new Group(rule, matchedTokens)
    }

    statementEnd(n=0) {
        return this._stmt_end_token.match(this.peek(n))
    }

    curr() {
        return this.tokens[this.cursor]
    }

    next(n=1) {
        if (this.cursor + n >= this.length)
            return null

        this.cursor += n

        return this.tokens[this.cursor]
    }

    peek(n=1) {
        if (this.cursor + n >= this.length)
            return null

        return this.tokens[this.cursor + n]
    }

    seek(idx) {
        this.cursor = Math.min(Math.max(idx, 0), this.length - 1)
    }

    nextStatement() {
        while (this.next())
            if (this.statementEnd())
                return this.next()
    }

    get length() {
        return this.tokens.length
    }
}

const stream_io_operator = new Rule(
    "stream_io_operator",
    new Rule(
        "std_operator_io",
        new TokenExp(TokenType.Syntax, /^std/, Replacement.Drop()),
        new TokenExp(TokenType.Op, /^::/, Replacement.Drop()),
        new TokenExp(TokenType.FuncName, /operator[<<|>>]/, Replacement.Modify(TokenProperty.Value, /^operator/, ''))
    ),
    new Rule(
        "std_stream_operator_io",
        new TokenExp(TokenType.Syntax, /^std/, Replacement.Drop()),
        new TokenExp(TokenType.Op, /^::/, Replacement.Drop()),
        new TokenExp(TokenType.Syntax, /^basic_.*stream<.*>/, Replacement.Drop()),
        new TokenExp(TokenType.Op, /^::/, Replacement.Drop()),
        new TokenExp(TokenType.FuncName, /^operator[<<|>>]/, Replacement.Modify(TokenProperty.Value, /^operator/, ''))
    )
)

const stream = new Rule(
    "stream",
    new Rule(
        "std_io",
        new TokenExp(TokenType.Syntax, /^std/),
        new TokenExp(TokenType.Op, /^::/),
        new TokenExp(TokenType.Variable, /c[in|out]|basic_.*stream<.*>/),
    ),
    new Rule(
        "basic_stream",
        new TokenExp(TokenType.Variable, /.*/, /basic_.*stream/)
    )
)

const stream_close = new Rule(
    "stream_close",
    new Rule(
        "endl",
        new TokenExp(TokenType.Variable, /PTR_endl<.*>.*/, Replacement.Modify(TokenProperty.Value, "std::endl"))
    ),
    new Rule(
        "wc_var",
        new TokenExp(TokenType.Variable, /.*/)
    )
)

const sm = new Rule("sm", new TokenExp(TokenType.Syntax, /^;/))

const stream_stmt = new Statement("stream_statement", stream_io_operator, stream, stream_close, sm)

fetch("/ghidra/output/sHWY0wnFVvWZ.json")
.then(response => response.json())
.then(data => {
    for (const fdata of Object.values(data)) {
        const tokens = fdata["tokens"]

        const parser = new Parser(tokens, true, true)

        do {
            const match = parser.match(stream_stmt)
            if (match) {
                parser.nextStatement()

                // const [op, stream, variable, sem] = match.groups.map(group => group.replace().tokens.map(token => token.value).join(''))
                const result = match.replace().reorder(stream, stream_io_operator, stream_close, sm)
                console.log(String(result))

                // console.log("Found:", stream, op, variable, sem)
            }
        } while (parser.next())
    }
})