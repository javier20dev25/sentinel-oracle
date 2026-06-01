"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseProvider = void 0;
class BaseProvider {
    constructor(name, model, apiKey) {
        this.name = name;
        this.model = model;
        this.apiKey = apiKey;
    }
    validateConfig() {
        return !!this.apiKey;
    }
}
exports.BaseProvider = BaseProvider;
