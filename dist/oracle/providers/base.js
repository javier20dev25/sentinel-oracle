export class BaseProvider {
    constructor(name, model, apiKey) {
        this.name = name;
        this.model = model;
        this.apiKey = apiKey;
    }
    validateConfig() {
        return !!this.apiKey;
    }
}
