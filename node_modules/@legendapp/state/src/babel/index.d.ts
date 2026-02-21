export default function (): {
    visitor: {
        ImportDeclaration: {
            enter(path: {
                node: any;
                replaceWith: (param: any) => any;
                skip: () => void;
            }): void;
        };
        JSXElement: {
            enter(path: {
                node: any;
                replaceWith: (param: any) => any;
                skip: () => void;
                traverse: (path: any) => any;
            }): void;
        };
    };
};
