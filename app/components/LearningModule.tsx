import React from 'react';

interface LearningModuleProps {
    title: string;
    description: string;
    examples: string[];
    resources: string[];
}

const LearningModule: React.FC<LearningModuleProps> = ({ title, description, examples, resources }) => {
    return (
        <div className="bg-white shadow-md rounded-lg p-4 mb-4">
            <h3 className="text-lg font-bold">{title}</h3>
            <p className="text-sm text-gray-700">{description}</p>
            <h4 className="font-semibold mt-2">Examples:</h4>
            <ul className="list-disc list-inside">
                {examples.map((example, index) => (
                    <li key={index}>{example}</li>
                ))}
            </ul>
            <h4 className="font-semibold mt-2">Resources:</h4>
            <ul className="list-disc list-inside">
                {resources.map((resource, index) => (
                    <li key={index}>
                        <a href={resource} target="_blank" rel="noopener noreferrer" className="text-blue-600 underline">
                            {resource}
                        </a>
                    </li>
                ))}
            </ul>
        </div>
    );
};

export default LearningModule; 